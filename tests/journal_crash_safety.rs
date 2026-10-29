//! Crash-safety gates for the mesh journal (`docs/spec/JOURNAL-CRASH-SAFETY.md`).
//!
//! Every case drives a **real file** on disk: the journal's whole claim is about
//! what a process leaves behind when it dies mid-write, and a mock cannot be
//! killed mid-`write(2)`. The torn cases are produced by truncating a real,
//! framingly-written journal at a real byte offset.

use std::path::{Path, PathBuf};

use tallow::mesh::journal::{checkpoint_hash, replay, write_snapshot_atomic, Event, Journal};

const DIGEST_LEN: usize = 16;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tallow-journal-crash-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Three framed records describing one complete, replayable wave.
fn append_wave(journal: &mut Journal, wave: usize) {
    journal
        .append(&Event::WaveStarted {
            wave,
            seed: wave as u64 + 1,
        })
        .expect("wave_started");
    journal
        .append(&Event::TaskCommitted {
            wave,
            task: format!("t{wave}"),
            result_hash: format!("h{wave}"),
        })
        .expect("task_committed");
    let checkpoint = checkpoint_hash(&[(format!("t{wave}"), format!("h{wave}"))]);
    journal
        .append(&Event::WaveEnded { wave, checkpoint })
        .expect("wave_ended");
}

fn wave_checkpoint(wave: usize) -> String {
    checkpoint_hash(&[(format!("t{wave}"), format!("h{wave}"))])
}

fn digest_of(text: &str) -> String {
    blake3::hash(text.as_bytes()).to_hex().to_string()[..DIGEST_LEN].to_string()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn truncate_to(path: &Path, len: u64) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for truncate");
    file.set_len(len).expect("set_len");
}

fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open for append");
    file.write_all(bytes).expect("write bytes");
}

/// Every line of a healthy journal is `<16 hex> <json>` and the digest matches.
fn assert_all_records_framed(path: &Path) {
    let text = std::fs::read_to_string(path).expect("read journal");
    assert!(text.ends_with('\n'), "a durable record ends with a newline");
    for (i, line) in text.lines().enumerate() {
        assert!(line.len() > DIGEST_LEN + 1, "line {} too short: {line}", i + 1);
        let (digest, rest) = line.split_at(DIGEST_LEN);
        assert!(
            rest.starts_with(' '),
            "line {} has no digest separator: {line}",
            i + 1
        );
        assert!(
            digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "line {} prefix is not a 16-hex digest: {digest}",
            i + 1
        );
        let json = &rest[1..];
        assert_eq!(
            digest,
            digest_of(json),
            "line {} digest does not cover its JSON",
            i + 1
        );
        serde_json::from_str::<serde_json::Value>(json)
            .unwrap_or_else(|e| panic!("line {} is not JSON after the frame: {e}", i + 1));
    }
}

// Gate 1 — torn tail.
#[test]
fn a_torn_tail_is_truncated_to_the_last_good_record() {
    let dir = scratch("torn-tail");
    let path = dir.join("journal.jsonl");

    {
        let mut journal = Journal::open(&path).expect("open");
        for wave in 0..3 {
            append_wave(&mut journal, wave);
        }
        // The fourth record overall opens wave 3; the file is then cut 10 bytes
        // short of its end, the shape a crash mid-append leaves behind.
        journal
            .append(&Event::WaveStarted { wave: 3, seed: 4 })
            .expect("wave 3 starts");
    }
    let intact_len = std::fs::metadata(&path).expect("metadata").len();
    // Length of the final record (the partial wave-3 start), so the expected
    // discard is its surviving bytes, not the 10 bytes that were cut.
    let before = std::fs::read_to_string(&path).expect("read");
    let last_record_start = before[..before.len() - 1]
        .rfind('\n')
        .map(|i| i + 1)
        .expect("more than one record");
    let last_record_len = before.len() - last_record_start;
    truncate_to(&path, intact_len - 10);

    let journal = Journal::open(&path).expect("a torn tail must not refuse the run");
    assert_eq!(
        journal.discarded_bytes(),
        (last_record_len - 10) as u64,
        "the number of discarded bytes is reported"
    );
    assert_eq!(journal.legacy_records(), 0);
    drop(journal);

    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        last_record_start as u64,
        "the file is truncated to the last good record"
    );
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(
        text.ends_with('\n'),
        "the recovered file ends at a record boundary"
    );

    let waves = replay(&path).expect("replay after recovery");
    assert_eq!(waves.len(), 3, "the three committed waves survive");
    for (i, wave) in waves.iter().enumerate() {
        assert_eq!(wave.wave, i);
        assert_eq!(wave.checkpoint, wave_checkpoint(i));
        assert_eq!(wave.tasks, 1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// Gate 2 — corrupt committed record.
#[test]
fn a_corrupt_committed_record_refuses_the_open_and_leaves_the_file_alone() {
    let dir = scratch("corrupt");
    let path = dir.join("journal.jsonl");

    {
        let mut journal = Journal::open(&path).expect("open");
        append_wave(&mut journal, 0);
        append_wave(&mut journal, 1);
    }

    // Flip one byte inside the JSON of a complete, newline-terminated record:
    // wave 1's `task_committed` is line 5.
    let mut bytes = std::fs::read(&path).expect("read");
    let needle = b"\"hash\":\"h1\"";
    let at = find(&bytes, needle).expect("the committed hash is in the file");
    let flipped = at + needle.len() - 2; // the 'h' of "h1"
    bytes[flipped] = b'X';
    std::fs::write(&path, &bytes).expect("write corrupted journal");

    let err = match Journal::open(&path) {
        Ok(_) => panic!("corruption of committed data must refuse"),
        Err(e) => e,
    };
    let message = err.to_string();
    assert!(
        message.contains("line 5"),
        "the refusal names the line: {message}"
    );
    assert!(
        message.contains("digest mismatch") || message.contains("corrupt"),
        "the refusal names the reason: {message}"
    );

    assert_eq!(
        std::fs::read(&path).expect("read back"),
        bytes,
        "a refused open must not rewrite the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// Gate 3 — clean round-trip.
#[test]
fn a_clean_journal_round_trips_byte_for_byte() {
    let dir = scratch("roundtrip");
    let path = dir.join("journal.jsonl");

    {
        let mut journal = Journal::open(&path).expect("open");
        for wave in 0..4 {
            append_wave(&mut journal, wave);
        }
    }
    let written = std::fs::read(&path).expect("read");
    assert_all_records_framed(&path);

    // Reopening a healthy journal must discover nothing to repair.
    let journal = Journal::open(&path).expect("reopen");
    assert_eq!(journal.discarded_bytes(), 0);
    assert_eq!(journal.legacy_records(), 0);
    drop(journal);

    assert_eq!(
        std::fs::read(&path).expect("read after reopen"),
        written,
        "open on a clean journal is read-only"
    );

    let waves = replay(&path).expect("replay");
    assert_eq!(waves.len(), 4);
    for (i, wave) in waves.iter().enumerate() {
        assert_eq!(wave.checkpoint, wave_checkpoint(i));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// Gate 4 — torn digest prefix.
#[test]
fn a_torn_digest_prefix_is_a_torn_tail_not_corruption() {
    let dir = scratch("torn-digest");
    let path = dir.join("journal.jsonl");

    {
        let mut journal = Journal::open(&path).expect("open");
        append_wave(&mut journal, 0);
        append_wave(&mut journal, 1);
    }
    let good_len = std::fs::metadata(&path).expect("metadata").len();

    // The crash landed inside the digest prefix: 12 hex chars, no space, no
    // newline, no JSON at all.
    append_bytes(&path, b"0123456789ab");
    assert_eq!(
        std::fs::metadata(&path).expect("metadata").len(),
        good_len + 12
    );

    let journal = Journal::open(&path).expect("an incomplete digest is a torn tail");
    assert_eq!(journal.discarded_bytes(), 12);
    drop(journal);

    assert_eq!(std::fs::metadata(&path).expect("metadata").len(), good_len);
    let waves = replay(&path).expect("replay");
    assert_eq!(waves.len(), 2);
    assert_eq!(waves[1].checkpoint, wave_checkpoint(1));
    let _ = std::fs::remove_dir_all(&dir);
}

// Gate 5 — legacy journal without a digest prefix.
#[test]
fn a_legacy_journal_opens_unchecked_and_new_appends_are_framed() {
    let dir = scratch("legacy");
    let path = dir.join("journal.jsonl");

    // Exactly what the previous writer produced: bare JSON, one object a line.
    let checkpoint = wave_checkpoint(7);
    let legacy_lines = [
        serde_json::json!({"kind": "wave_started", "wave": 7, "seed": 8}).to_string(),
        serde_json::json!({"kind": "task_committed", "wave": 7, "task": "t7", "hash": "h7"})
            .to_string(),
        serde_json::json!({"kind": "wave_ended", "wave": 7, "checkpoint": checkpoint}).to_string(),
    ];
    let legacy = format!("{}\n", legacy_lines.join("\n"));
    std::fs::write(&path, legacy.as_bytes()).expect("write legacy journal");

    let mut journal = Journal::open(&path).expect("a legacy journal still opens");
    assert_eq!(
        journal.legacy_records(),
        3,
        "legacy records are counted once"
    );
    assert_eq!(journal.discarded_bytes(), 0);

    // New appends are framed; mixing is allowed and the legacy count is stable.
    journal
        .append(&Event::RunStopped { drained: true })
        .expect("framed append onto a legacy journal");
    drop(journal);

    let text = std::fs::read_to_string(&path).expect("read");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(
        &lines[..3],
        &legacy_lines.iter().map(String::as_str).collect::<Vec<_>>()[..],
        "legacy lines are left exactly as they were"
    );
    let last = lines[3];
    let (digest, rest) = last.split_at(DIGEST_LEN);
    assert!(rest.starts_with(' '), "the new record is framed: {last}");
    assert_eq!(
        digest,
        digest_of(&rest[1..]),
        "the new record's digest covers its JSON"
    );

    let journal = Journal::open(&path).expect("reopen the mixed journal");
    assert_eq!(
        journal.legacy_records(),
        3,
        "counted once, not once per open"
    );
    drop(journal);
    let waves = replay(&path).expect("mixed replay");
    assert_eq!(waves.len(), 1);
    assert_eq!(waves[0].wave, 7);
    assert_eq!(waves[0].checkpoint, checkpoint);
    let _ = std::fs::remove_dir_all(&dir);
}

// Rule 4 — truncation is tail-only. A torn record with committed history after
// it is corruption; silently discarding it would lose committed history.
#[test]
fn a_mid_file_torn_line_blocks_the_open() {
    let dir = scratch("mid-file");
    let path = dir.join("journal.jsonl");

    {
        let mut journal = Journal::open(&path).expect("open");
        append_wave(&mut journal, 0);
    }
    let framed = std::fs::read(&path).expect("read");

    // Splice a torn, newline-terminated line between record 3 and record 4:
    // the shape you get when an append is glued onto a partial write.
    let after_third = framed
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(2)
        .map(|(i, _)| i + 1)
        .expect("at least three lines");
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&framed[..after_third]);
    spliced.extend_from_slice(b"{\"kind\":\"wave_started\",\"wave\":1\n");
    spliced.extend_from_slice(&framed[after_third..]);
    std::fs::write(&path, &spliced).expect("write spliced journal");

    let err = match Journal::open(&path) {
        Ok(_) => panic!("a torn record with committed history after it is corruption"),
        Err(e) => e,
    };
    let message = err.to_string();
    assert!(message.contains("line 4"), "names the torn line: {message}");
    assert_eq!(
        std::fs::read(&path).expect("read back"),
        spliced,
        "a refused open must not truncate committed history"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// The rotation report is rewritten, not appended: temp -> sync_data -> rename.
#[test]
fn a_snapshot_is_replaced_atomically_and_leaves_no_temp_file() {
    let dir = scratch("snapshot");
    let path = dir.join("rotation-report.json");

    let long = vec![b'x'; 64 * 1024];
    write_snapshot_atomic(&path, &long).expect("first snapshot");
    assert_eq!(std::fs::read(&path).expect("read"), long);

    // A shorter second snapshot must replace the whole file, not overwrite a
    // prefix of it — that is what distinguishes rename from truncate+write.
    write_snapshot_atomic(&path, b"{\"status\":\"no_state\"}\n").expect("second snapshot");
    assert_eq!(
        std::fs::read(&path).expect("read"),
        b"{\"status\":\"no_state\"}\n"
    );

    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|name| name != "rotation-report.json")
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temp file survives a successful rename: {leftovers:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// The doctor wiring: `--rotation-report-out PATH` writes the snapshot atomically.
#[test]
fn the_rotation_report_snapshot_is_written_by_the_doctor_verb() {
    let dir = scratch("rotation-cli");
    let path = dir.join("rotation-report.json");

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("doctor")
        .arg("--rotation")
        .arg("--rotation-report-out")
        .arg(&path)
        .output()
        .expect("run tallow doctor --rotation");
    assert!(
        out.status.success(),
        "doctor --rotation must succeed without a state file: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let written = std::fs::read_to_string(&path).expect("report snapshot exists");
    let report: serde_json::Value = serde_json::from_str(&written).expect("snapshot is JSON");
    assert_eq!(report["schema"], "tallow.doctor.rotation.v1");
    assert_eq!(report["status"], "no_state");
    assert!(
        written.ends_with('\n'),
        "the snapshot is a complete, newline-terminated document"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
