//! M4 acceptance: a real socket, real processes, and a partition.
//!
//! What this proves, in order, because each is a separate claim:
//!
//! 1. Two `tallow mesh worker` processes join a coordinator over TCP, each
//!    signing its frames with its own Ed25519 key.
//! 2. The plan runs across them and commits the SAME checkpoints as a local
//!    reference run — the M1 determinism gate, now across a wire.
//! 3. A node frozen with SIGSTOP stops answering; its lease expires, the task is
//!    reassigned at a higher epoch, the replacement commits, and the frozen
//!    node's late answer is DISCARDED rather than double-committed.
//! 4. `simulated` is per node: the node that committed reports false, the one
//!    that only joined still reports true.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use tallow::mesh::remote::{local_checkpoints, MeshServer};
use tallow::mesh::wire::hex;
use tallow::mesh::{Task, TaskClass};

struct Worker {
    child: Child,
    pid: u32,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = Command::new("kill").arg("-CONT").arg(self.pid.to_string()).output();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_worker(addr: &str, node: &str, seed: u8, server_key: &str, run_id: &str) -> Worker {
    let key = hex(&[seed; 32]);
    let child = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "mesh", "worker", "--connect", addr, "--node", node, "--key", &key,
            "--server-key", server_key, "--run-id", run_id,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn worker");
    let pid = child.id();
    Worker { child, pid }
}

#[test]
fn a_partitioned_node_is_fenced_and_its_late_answer_discarded() {
    let run_id = format!("run-{}", std::process::id());
    let server_key = SigningKey::from_bytes(&[1u8; 32]);
    let server_vk = server_key.verifying_key();
    let w1_key = SigningKey::from_bytes(&[11u8; 32]);
    let w2_key = SigningKey::from_bytes(&[12u8; 32]);

    let server = MeshServer::bind(
        "127.0.0.1:0",
        &run_id,
        server_key,
        vec![
            ("w1".to_string(), w1_key.verifying_key()),
            ("w2".to_string(), w2_key.verifying_key()),
        ],
    )
    .expect("bind");
    let addr = server.addr().to_string();
    let pubkey = hex(server_vk.as_bytes());

    let w1 = spawn_worker(&addr, "w1", 11, &pubkey, &run_id);
    let _w2 = spawn_worker(&addr, "w2", 12, &pubkey, &run_id);

    let deadline = Instant::now() + Duration::from_secs(15);
    while server.node_status().len() < 2 {
        assert!(Instant::now() < deadline, "workers did not join: {:?}", server.node_status());
        std::thread::sleep(Duration::from_millis(50));
    }
    // Both joined, neither has committed: both must still report simulated.
    assert!(
        server.node_status().iter().all(|n| n.simulated),
        "a node that only joined must not claim to be real: {:?}",
        server.node_status()
    );

    // Six instant tasks in one wave. w1 is frozen while it holds three of them,
    // so those leases expire and the tasks are reassigned to w2. A task slower
    // than its own lease would be reassigned forever — that is a defect the
    // coordinator now refuses (attempt cap), not a way to stage a partition, so
    // the partition is staged by freezing the holder instead.
    let tasks: Vec<Task> = (0..6)
        .map(|i| Task::new(&format!("t{i}"), "hash", vec![], TaskClass::Pure, None))
        .collect();

    let journal = std::env::temp_dir().join(format!("mesh-remote-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&journal);

    // Freeze w1 BEFORE the plan starts. A timer-based freeze races the work: six
    // instant tasks all finished before an 80 ms freeze could land, which made
    // the test assert a reassignment that never happened. Freezing first is the
    // partition the test means to stage — a peer that is present and unreachable.
    Command::new("kill")
        .arg("-STOP")
        .arg(w1.pid.to_string())
        .output()
        .expect("freeze w1");

    let report = server
        .run_plan(&tasks, 99, journal.to_str().unwrap(), 300)
        .expect("run over the wire");
    // 1. Every task committed, and the checkpoints match a local reference run.
    let local = local_checkpoints(&tasks, 99).expect("local reference");
    let remote: Vec<String> = report.waves.iter().map(|(_, _, cp)| cp.clone()).collect();
    assert_eq!(remote, local, "remote checkpoints diverged from the local reference");

    // 2. The partition was real: a lease expired and work moved.
    assert!(report.reassigned >= 1, "expected a reassignment, got {}", report.reassigned);

    // 3. `simulated` is per node: only a committed result makes a node real.
    let statuses = server.node_status();
    let w1_status = statuses.iter().find(|n| n.name == "w1").expect("w1 present");
    assert!(w1_status.simulated, "w1 never committed; it must not claim to be real");
    let w2_status = statuses.iter().find(|n| n.name == "w2").expect("w2 present");
    assert!(w2_status.committed >= 1, "w2 ran the reassigned work");
    assert!(!w2_status.simulated, "a node with a committed task is real");

    // 4. Exactly one commit per task, and thawing the frozen node adds none.
    let count = |p: &std::path::Path| {
        std::fs::read_to_string(p)
            .unwrap_or_default()
            .matches("task_committed")
            .count()
    };
    assert_eq!(count(&journal), 6, "exactly one commit per task");
    let _ = Command::new("kill").arg("-CONT").arg(w1.pid.to_string()).output();
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(count(&journal), 6, "a thawed node's stale answers must not commit again");
}

#[test]
fn an_untrusted_key_cannot_join() {
    let run_id = "run-untrusted";
    let server_key = SigningKey::from_bytes(&[1u8; 32]);
    let pubkey = hex(server_key.verifying_key().as_bytes());
    let server = MeshServer::bind(
        "127.0.0.1:0",
        run_id,
        server_key,
        vec![("w1".to_string(), SigningKey::from_bytes(&[11u8; 32]).verifying_key())],
    )
    .expect("bind");
    let addr = server.addr().to_string();

    // Claims to be w1, signs with a key nobody authorised.
    let mut child = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "mesh", "worker", "--connect", &addr, "--node", "w1",
            "--key", &hex(&[99u8; 32]), "--server-key", &pubkey, "--run-id", run_id,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("wait") {
            assert!(!status.success(), "an unauthorised join must fail");
            break;
        }
        assert!(Instant::now() < deadline, "worker hung instead of being refused");
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(server.node_status().is_empty(), "no peer may be registered");
    let _ = child.kill();
}

#[test]
fn a_run_without_nodes_fails_instead_of_hanging() {
    let server_key = SigningKey::from_bytes(&[1u8; 32]);
    let server = MeshServer::bind("127.0.0.1:0", "run-empty", server_key, vec![]).expect("bind");
    let tasks = vec![Task::new("a", "hash", vec![], TaskClass::Pure, None)];
    let journal = std::env::temp_dir().join(format!("mesh-empty-{}.jsonl", std::process::id()));
    let started = Instant::now();
    let err = server
        .run_plan(&tasks, 1, journal.to_str().unwrap(), 100)
        .expect_err("no nodes must be refused");
    assert!(err.contains("no nodes joined"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[allow(dead_code)]
fn _read_first_line(mut child: Child) -> String {
    let out = child.stdout.take().expect("stdout");
    let mut line = String::new();
    let _ = BufReader::new(out).read_line(&mut line);
    line
}

#[test]
fn a_stopped_worker_leaves_the_live_table_and_returns() {
    let run_id = format!("run-live-{}", std::process::id());
    let server_key = SigningKey::from_bytes(&[21u8; 32]);
    let server_vk = server_key.verifying_key();
    let w_key = SigningKey::from_bytes(&[22u8; 32]);

    let server = MeshServer::bind(
        "127.0.0.1:0",
        &run_id,
        server_key,
        vec![("w1".to_string(), w_key.verifying_key())],
    )
    .expect("bind");
    let addr = server.addr().to_string();
    let pubkey = hex(server_vk.as_bytes());

    let w1 = spawn_worker(&addr, "w1", 22, &pubkey, &run_id);

    fn wait_for(
        server: &MeshServer,
        budget: Duration,
        what: &str,
        pred: impl Fn(&MeshServer) -> bool,
    ) {
        let deadline = Instant::now() + budget;
        while !pred(server) {
            assert!(Instant::now() < deadline, "{what}: {:?}", server.node_status());
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // Join is not liveness: the socket opens first, the first heartbeat follows.
    wait_for(&server, Duration::from_secs(15), "worker did not join", |s| {
        s.node_status().first().is_some()
    });
    wait_for(&server, Duration::from_secs(10), "worker never sent a heartbeat", |s| {
        s.node_status().first().is_some_and(|n| n.live)
    });
    assert!(
        server.node_status()[0].simulated,
        "a live node that committed nothing is still simulated"
    );

    // Stopped, not disconnected: the TCP connection stays open, so only the
    // heartbeat horizon can tell the coordinator this node is gone.
    Command::new("kill")
        .arg("-STOP")
        .arg(w1.pid.to_string())
        .output()
        .expect("freeze worker");
    wait_for(
        &server,
        Duration::from_secs(10),
        "stopped worker stayed live past 3 x interval",
        |s| s.node_status().first().map(|n| !n.live).unwrap_or(true),
    );
    assert!(
        server.node_status().first().is_some_and(|n| n.simulated),
        "a stopped node must report simulated: {:?}",
        server.node_status()
    );

    Command::new("kill")
        .arg("-CONT")
        .arg(w1.pid.to_string())
        .output()
        .expect("thaw worker");
    wait_for(
        &server,
        Duration::from_secs(10),
        "thawed worker did not resume heartbeating",
        |s| s.node_status().first().map(|n| n.live).unwrap_or(false),
    );
    assert!(
        server.node_status().first().is_some_and(|n| n.live),
        "after SIGCONT the node must be listed and live: {:?}",
        server.node_status()
    );
}

#[test]
fn work_is_not_assigned_to_a_node_that_stopped_heartbeating() {
    let run_id = format!("run-skip-{}", std::process::id());
    let server_key = SigningKey::from_bytes(&[31u8; 32]);
    let w1_key = SigningKey::from_bytes(&[32u8; 32]);
    let w2_key = SigningKey::from_bytes(&[33u8; 32]);

    let server = MeshServer::bind(
        "127.0.0.1:0",
        &run_id,
        server_key.clone(),
        vec![
            ("w1".to_string(), w1_key.verifying_key()),
            ("w2".to_string(), w2_key.verifying_key()),
        ],
    )
    .expect("bind");
    let addr = server.addr().to_string();
    let pubkey = hex(server_key.verifying_key().as_bytes());

    let w1 = spawn_worker(&addr, "w1", 32, &pubkey, &run_id);
    let _w2 = spawn_worker(&addr, "w2", 33, &pubkey, &run_id);

    let deadline = Instant::now() + Duration::from_secs(20);
    while server.node_status().iter().filter(|n| n.live).count() < 2 {
        assert!(Instant::now() < deadline, "workers did not heartbeat: {:?}", server.node_status());
        std::thread::sleep(Duration::from_millis(50));
    }

    // Freeze w1 and wait for the table to notice, *before* the plan starts.
    // This is the case the peer table alone cannot see: the socket is open.
    Command::new("kill").arg("-STOP").arg(w1.pid.to_string()).output().expect("freeze");
    let deadline = Instant::now() + Duration::from_secs(15);
    while server.node_status().iter().any(|n| n.name == "w1" && n.live) {
        assert!(Instant::now() < deadline, "w1 stayed live past the horizon");
        std::thread::sleep(Duration::from_millis(50));
    }

    let tasks: Vec<Task> = (0..4)
        .map(|i| Task::new(&format!("t{i}"), "hash", vec![], TaskClass::Pure, None))
        .collect();
    let journal = std::env::temp_dir().join(format!("mesh-skip-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&journal);

    let report = server
        .run_plan(&tasks, 7, journal.to_str().unwrap(), 300)
        .expect("run over the wire");
    let local = local_checkpoints(&tasks, 7).expect("local reference");
    let remote: Vec<String> = report.waves.iter().map(|(_, _, cp)| cp.clone()).collect();
    assert_eq!(remote, local, "results must still match the local reference");

    let statuses = server.node_status();
    let w1_status = statuses.iter().find(|n| n.name == "w1").expect("w1 present");
    let w2_status = statuses.iter().find(|n| n.name == "w2").expect("w2 present");
    assert_eq!(
        w1_status.committed, 0,
        "a node that stopped heartbeating must receive no work: {:?}",
        statuses
    );
    assert_eq!(w2_status.committed, 4, "the live node ran everything: {:?}", statuses);
    assert_eq!(report.reassigned, 0, "nothing needed reassignment — it was never sent");

    let _ = Command::new("kill").arg("-CONT").arg(w1.pid.to_string()).output();
}
