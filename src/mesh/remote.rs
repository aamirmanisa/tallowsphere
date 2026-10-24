//! Mesh over a real socket: coordinator server and worker client.
//!
//! The in-process coordinator (M1–M3) owns its workers, so a straggler can be
//! fenced by an epoch and a stale commit refused. Over a wire the same fence has
//! to survive the things a thread cannot do: a peer that stops answering
//! entirely (SIGSTOP, a dropped route, a hung VM), a result that arrives after
//! its lease was reassigned, and a peer that claims a result it did not compute.
//!
//! Semantics are unchanged from M1: a lease is `(task, epoch)`; a result commits
//! only if its epoch is the current one; a reassignment increments the epoch, so
//! the slow worker's late answer is discarded rather than duplicated. What M4
//! adds is that the fence is enforced across processes, and that a node is only
//! reported as real (`simulated = false`) after it has completed a join
//! handshake AND had one result committed — not because it connected.
//!
//! Deliberately absent: speculative duplicate execution over the wire. Speculation
//! doubles the work and the bandwidth, and the M3 evidence showed it only pays
//! when the straggler is slow rather than gone. Reassignment covers "gone".

use crate::mesh::journal::{checkpoint_hash, Event, Journal};
use crate::mesh::membership::{Membership, HEARTBEAT};
use crate::mesh::wire::{
    hex, key_from_seed, read_frame, write_frame, Envelope, Trust, MAX_FRAME,
};
use crate::mesh::{plan as mesh_plan, Task};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// What a node did and whether the coordinator is allowed to call it real.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub name: String,
    pub joined: bool,
    /// Whether a heartbeat arrived within `3 × interval`. A node whose process
    /// is stopped keeps its TCP connection open, so this is the only honest
    /// liveness signal the coordinator has.
    pub live: bool,
    pub committed: u64,
    /// True until the node has both joined and committed one task. Flipping this
    /// on connection alone would let a node that never ran anything report
    /// itself as a working part of the mesh.
    pub simulated: bool,
}

#[derive(Debug)]
pub struct RemoteReport {
    pub waves: Vec<(usize, usize, String)>,
    pub nodes: Vec<NodeStatus>,
    pub reassigned: u64,
    pub discarded_stale: u64,
}

struct Peer {
    name: String,
    tx: Sender<Envelope>,
    committed: u64,
}

pub struct MeshServer {
    addr: SocketAddr,
    key: SigningKey,
    run_id: String,
    trust: Arc<Mutex<Trust>>,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    membership: Arc<Mutex<Membership>>,
    inbound: Receiver<Envelope>,
    stop: Arc<AtomicBool>,
    nonce: AtomicU64,
}

impl MeshServer {
    /// Bind and start accepting. `node_keys` maps node names to the public keys
    /// that may speak for them; anything else is refused at join.
    pub fn bind(
        addr: &str,
        run_id: &str,
        key: SigningKey,
        node_keys: Vec<(String, VerifyingKey)>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        let mut trust = Trust::new();
        for (name, vk) in node_keys {
            trust = trust.allow_node(&name, vk);
        }
        let trust = Arc::new(Mutex::new(trust));
        let peers: Arc<Mutex<HashMap<String, Peer>>> = Arc::new(Mutex::new(HashMap::new()));
        // Twice the worker's send interval, so two heartbeats must be lost before
        // a live node is declared gone.
        let membership = Arc::new(Mutex::new(Membership::new_after_verification(
            std::time::Duration::from_millis(500),
        )));
        let (tx, inbound) = channel();
        let stop = Arc::new(AtomicBool::new(false));
        let server_key = key.clone();
        let run = run_id.to_string();

        let accept_trust = Arc::clone(&trust);
        let accept_peers = Arc::clone(&peers);
        let accept_membership = Arc::clone(&membership);
        let accept_stop = Arc::clone(&stop);
        thread::spawn(move || {
            for stream in listener.incoming() {
                if accept_stop.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(stream) = stream else { continue };
                let _ = stream.set_nodelay(true);
                let tx = tx.clone();
                let trust = Arc::clone(&accept_trust);
                let peers = Arc::clone(&accept_peers);
                let membership = Arc::clone(&accept_membership);
                let key = server_key.clone();
                let run = run.clone();
                let stop = Arc::clone(&accept_stop);
                thread::spawn(move || {
                    let _ = serve_connection(stream, run, key, trust, peers, membership, tx, stop);
                });
            }
        });

        Ok(MeshServer {
            addr,
            key,
            run_id: run_id.to_string(),
            trust,
            peers,
            membership,
            inbound,
            stop,
            nonce: AtomicU64::new(1),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn pubkey_hex(&self) -> String {
        hex(self.key.verifying_key().as_bytes())
    }

    fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::Relaxed)
    }

    fn send_to(&self, node: &str, kind: &str, wave: u64, payload: Value) -> Result<(), String> {
        let mut env = Envelope::new(kind, &self.run_id, wave, "coordinator", self.next_nonce(), payload);
        env.sign(&self.key);
        let peers = self.peers.lock().map_err(|_| "peers poisoned".to_string())?;
        let peer = peers.get(node).ok_or_else(|| format!("no peer {node}"))?;
        peer.tx.send(env).map_err(|_| format!("peer {node} closed"))
    }

    /// Nodes that joined, in join order, with their current status.
    pub fn node_status(&self) -> Vec<NodeStatus> {
        let peers = match self.peers.lock() {
            Ok(p) => p,
            Err(_) => return Vec::new(),
        };
        let membership = match self.membership.lock() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        let now = Instant::now();
        let mut out: Vec<NodeStatus> = peers
            .values()
            .map(|p| NodeStatus {
                name: p.name.clone(),
                // `joined` now means "the handshake completed"; `live` is the
                // heartbeat question, answered by the table. A SIGSTOPped node
                // keeps its socket open, so the socket alone cannot answer it.
                joined: true,
                live: membership.is_live(&p.name, now),
                committed: p.committed,
                simulated: membership.is_simulated(&p.name, now),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// Run a plan across the connected nodes.
    ///
    /// `lease_ms` bounds how long a task may sit with one node before the
    /// coordinator reassigns it at a higher epoch. `engine` decides what a task
    /// computes; it must be deterministic in `(func, seed, wave, task)` — the
    /// checkpoint comparison depends on that.
    pub fn run_plan(
        &self,
        tasks: &[Task],
        mesh_seed: u64,
        journal_path: &str,
        lease_ms: u64,
    ) -> Result<RemoteReport, String> {
        let waves = mesh_plan(tasks).map_err(|e| format!("plan: {e}"))?;
        let mut journal = Journal::open(journal_path).map_err(|e| format!("journal: {e}"))?;
        journal
            .append(&Event::RunStarted {
                run_id: self.run_id.clone(),
                mesh_seed,
                tasks: tasks.len(),
            })
            .map_err(|e| e.to_string())?;

        let mut report = RemoteReport {
            waves: Vec::new(),
            nodes: Vec::new(),
            reassigned: 0,
            discarded_stale: 0,
        };

        for (wave_index, wave) in waves.iter().enumerate() {
            let wave_seed = crate::mesh::wave_seed(mesh_seed, wave_index);
            journal
                .append(&Event::WaveStarted {
                    wave: wave_index,
                    seed: wave_seed,
                })
                .map_err(|e| e.to_string())?;

            // lease per task: (epoch, deadline, holder)
            let mut leases: HashMap<String, (u64, Instant, String)> = HashMap::new();
            let mut committed: HashMap<String, String> = HashMap::new();
            let mut rotating = 0usize;

            for task in &wave.tasks {
                let holder = self.pick_node(rotating)?;
                rotating += 1;
                self.send_to(
                    &holder,
                    "assign",
                    wave_index as u64,
                    json!({
                        "task": task.id,
                        "func": task.func,
                        "seed": wave_seed,
                        "task_seed": crate::mesh::task_seed(mesh_seed, wave_index, &task.id, 1),
                        "attempt": 1,
                        "epoch": 1,
                    }),
                )?;
                leases.insert(task.id.clone(), (1, Instant::now() + Duration::from_millis(lease_ms), holder));
            }

            while committed.len() < wave.tasks.len() {
                if self.stop.load(Ordering::Relaxed) {
                    journal
                        .append(&Event::RunStopped { drained: false })
                        .map_err(|e| e.to_string())?;
                    return Err("stopped".to_string());
                }
                match self.inbound.recv_timeout(Duration::from_millis(5)) {
                    Ok(env) => {
                        if env.kind == "result" {
                            let task = env.payload["task"].as_str().unwrap_or_default().to_string();
                            let epoch = env.payload["epoch"].as_u64().unwrap_or(0);
                            let hash = env.payload["hash"].as_str().unwrap_or_default().to_string();
                            let wave_ok = env.wave == wave_index as u64;
                            let current = leases.get(&task).cloned();
                            match (wave_ok, current) {
                                (true, Some((live_epoch, _, holder))) if epoch == live_epoch && !committed.contains_key(&task) => {
                                    if env.node != holder {
                                        report.discarded_stale += 1;
                                        continue;
                                    }
                                    journal
                                        .append(&Event::TaskCommitted {
                                            wave: wave_index,
                                            task: task.clone(),
                                            result_hash: hash.clone(),
                                        })
                                        .map_err(|e| e.to_string())?;
                                    committed.insert(task, hash);
                                    if let Ok(mut peers) = self.peers.lock() {
                                        if let Some(p) = peers.get_mut(&env.node) {
                                            p.committed += 1;
                                        }
                                    }
                                }
                                _ => {
                                    // A late answer from a lease that was already
                                    // reassigned. Discarded, and said so — silently
                                    // accepting it would be a double commit.
                                    report.discarded_stale += 1;
                                }
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }

                // Reassign anything whose lease expired. The epoch bump is what
                // makes the old holder's eventual answer harmless.
                let expired: Vec<(String, u64, String)> = leases
                    .iter()
                    .filter(|(id, (_, deadline, _))| !committed.contains_key(*id) && Instant::now() > *deadline)
                    .map(|(id, (epoch, _, holder))| (id.clone(), *epoch, holder.clone()))
                    .collect();
                for (task, epoch, holder) in expired {
                    let Some(task_def) = wave.tasks.iter().find(|t| t.id == task) else { continue };
                    // A lease that keeps expiring must terminate the wave, not
                    // spin: without this, a task slower than its lease is
                    // reassigned forever and the run answers nothing.
                    if epoch as u32 >= task_def.class.max_attempts() {
                        journal
                            .append(&Event::TaskFailed {
                                wave: wave_index,
                                task: task.clone(),
                                reason: format!(
                                    "lease expired {} time(s); {} allows {} attempt(s)",
                                    epoch,
                                    task_def.class.as_str(),
                                    task_def.class.max_attempts()
                                ),
                            })
                            .map_err(|e| e.to_string())?;
                        return Err(format!(
                            "task {task} exhausted {} attempt(s) after lease expiry",
                            task_def.class.max_attempts()
                        ));
                    }
                    let Ok(next_holder) = self.pick_node_excluding(rotating, &[holder.clone()]) else {
                        continue;
                    };
                    rotating += 1;
                    let new_epoch = epoch + 1;
                    // A pure task's seed must not depend on the attempt: "pure"
                    // means re-executing produces the same result, and a
                    // reassignment is exactly such a re-execution. Folding the
                    // attempt in would make a partitioned run commit a different
                    // checkpoint than an uninterrupted one.
                    let seed_attempt = if task_def.class == crate::mesh::TaskClass::Pure {
                        1
                    } else {
                        new_epoch as u32
                    };
                    self.send_to(
                        &next_holder,
                        "assign",
                        wave_index as u64,
                        json!({
                            "task": task,
                            "func": task_def.func,
                            "seed": wave_seed,
                            "task_seed": crate::mesh::task_seed(mesh_seed, wave_index, &task, seed_attempt),
                            "attempt": new_epoch,
                            "epoch": new_epoch,
                        }),
                    )?;
                    journal
                        .append(&Event::TaskRetried {
                            wave: wave_index,
                            task: task.clone(),
                            attempt: new_epoch as u32,
                            reason: format!("lease expired with {holder}"),
                        })
                        .map_err(|e| e.to_string())?;
                    leases.insert(task.clone(), (new_epoch, Instant::now() + Duration::from_millis(lease_ms), next_holder));
                    report.reassigned += 1;
                }
            }

            let ordered: Vec<(String, String)> = {
                let mut v: Vec<(String, String)> = committed.into_iter().collect();
                v.sort();
                v
            };
            let checkpoint = checkpoint_hash(&ordered);
            journal
                .append(&Event::WaveEnded {
                    wave: wave_index,
                    checkpoint: checkpoint.clone(),
                })
                .map_err(|e| e.to_string())?;
            report.waves.push((wave_index, wave.tasks.len(), checkpoint));
        }

        report.nodes = self.node_status();
        Ok(report)
    }

    fn pick_node(&self, offset: usize) -> Result<String, String> {
        self.pick_node_excluding(offset, &[])
    }

    /// Choose a holder, never the node that just let the lease expire.
    ///
    /// Reassigning to the same peer is how a partition turns into an attempt
    /// exhaustion: the dead node keeps winning the rotation and the task burns
    /// its retries without ever meeting a live worker.
    fn pick_node_excluding(&self, offset: usize, exclude: &[String]) -> Result<String, String> {
        let peers = self.peers.lock().map_err(|_| "peers poisoned".to_string())?;
        if peers.is_empty() {
            return Err("no nodes joined".to_string());
        }
        // Assignment is where liveness has to matter. A node that stopped
        // heartbeating keeps its socket, so the peer table alone would hand it
        // work it cannot do and the wave would wait for a lease to expire.
        let live: Option<Vec<&String>> = self.membership.lock().ok().map(|m| {
            let now = Instant::now();
            peers
                .keys()
                .filter(|n| m.is_live(n, now))
                .filter(|n| !exclude.contains(n))
                .collect()
        });
        let mut names: Vec<&String> = match live {
            Some(v) if !v.is_empty() => v,
            // No heartbeat yet (a run that starts immediately after join) or all
            // nodes silent: fall back to the connected set rather than stranding
            // the wave. The lease still fences whatever does not answer.
            _ => peers.keys().filter(|n| !exclude.contains(n)).collect(),
        };
        if names.is_empty() {
            names = peers.keys().collect();
        }
        names.sort();
        Ok(names[offset % names.len()].clone())
    }
}

fn serve_connection(
    mut stream: TcpStream,
    run_id: String,
    key: SigningKey,
    trust: Arc<Mutex<Trust>>,
    peers: Arc<Mutex<HashMap<String, Peer>>>,
    membership: Arc<Mutex<Membership>>,
    inbound: Sender<Envelope>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    // Handshake: the first frame must be a signed `join`. Frames are decoded by
    // a buffered reader so a slow peer cannot corrupt the stream.
    let mut reader = crate::mesh::wire::FrameReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let deadline = Instant::now() + Duration::from_secs(10);
    let join = loop {
        match reader.next() {
            Ok(Some(env)) => break env,
            Ok(None) => {
                if Instant::now() > deadline {
                    return Err("handshake: timed out waiting for join".to_string());
                }
                continue;
            }
            Err(e) => return Err(format!("handshake read: {e}")),
        }
    };
    if join.kind != "join" || join.run_id != run_id {
        return Err("handshake: expected join for this run".to_string());
    }
    {
        let mut t = trust.lock().map_err(|_| "trust poisoned".to_string())?;
        if let Err(reason) = t.accept_node(&join) {
            // Say why, signed, before closing. A silent close looks like a
            // network blip to the worker, and a worker that reports "joined"
            // after being refused is a lie the operator would act on.
            let mut refused = Envelope::new(
                "refused",
                &run_id,
                0,
                "coordinator",
                join.nonce,
                json!({"reason": reason}),
            );
            refused.sign(&key);
            let _ = write_frame(&mut stream, &refused);
            return Err(format!("join refused: {reason}"));
        }
    }
    let node = join.node.clone();

    let mut welcome = Envelope::new(
        "welcome",
        &run_id,
        0,
        "coordinator",
        join.nonce,
        json!({"run_id": run_id, "frame_limit": MAX_FRAME}),
    );
    welcome.sign(&key);
    write_frame(&mut stream, &welcome).map_err(|e| format!("welcome: {e}"))?;
    // The handshake is complete from here on: heartbeats are now acceptable for
    // this node, and until one arrives the node is present but not live.
    if let Ok(mut m) = membership.lock() {
        m.handshaken(&node, Instant::now());
    }

    let (out_tx, out_rx) = channel::<Envelope>();
    peers
        .lock()
        .map_err(|_| "peers poisoned".to_string())?
        .insert(
            node.clone(),
            Peer {
                name: node.clone(),
                tx: out_tx,
                committed: 0,
            },
        );

    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let writer_thread = thread::spawn(move || {
        while let Ok(env) = out_rx.recv() {
            if write_frame(&mut writer, &env).is_err() {
                break;
            }
        }
    });

    while !stop.load(Ordering::Relaxed) {
        match reader.next() {
            Ok(None) => continue,
            Ok(Some(env)) => {
                let mut t = match trust.lock() {
                    Ok(t) => t,
                    Err(_) => break,
                };
                if t.accept_node(&env).is_err() {
                    continue;
                }
                drop(t);
                if env.kind == HEARTBEAT {
                    // Verified above; do not verify twice — the nonce guard
                    // would treat the second pass as a replay.
                    if let Ok(mut m) = membership.lock() {
                        let _ = m.observe_after_verification(&env, Instant::now());
                    }
                    continue;
                }
                if env.kind == "result" {
                    if let Ok(mut m) = membership.lock() {
                        m.committed(&env.node);
                    }
                }
                if inbound.send(env).is_err() {
                    if std::env::var("TALLOW_DEBUG_MESH").is_ok() {
                        eprintln!("[srv] {node}: inbound closed, dropping peer");
                    }
                    break;
                }
            }
            // A read timeout is not a disconnect. A worker frozen with SIGSTOP
            // keeps its socket open and simply stops sending; treating the
            // timeout as EOF removed the peer from the table, which made a
            // "stopped" node indistinguishable from a departed one — and hid it
            // from the liveness check entirely.
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted =>
            {
                continue
            }
            Err(e) => {
                if std::env::var("TALLOW_DEBUG_MESH").is_ok() {
                    eprintln!("[srv] {node}: read error {e:?}, dropping peer");
                }
                break;
            }
        }
    }
    if let Ok(mut p) = peers.lock() {
        p.remove(&node);
    }
    let _ = writer_thread.join();
    Ok(())
}

/// Worker side: connect, join, then execute assignments until the socket closes.
///
/// A task's `func` names what to compute. `sleep:<ms>` waits, `hash` returns
/// immediately; both derive the result from `(func, seed, wave, id)`, so any
/// node computes the same value and a checkpoint comparison across a local and
/// a remote run is a real equality test rather than a coincidence.
pub fn run_worker(
    connect: &str,
    node: &str,
    seed: [u8; 32],
    server_vk: VerifyingKey,
    run_id: &str,
) -> Result<(), String> {
    let addr: SocketAddr = connect
        .to_socket_addrs()
        .map_err(|e| format!("resolve {connect}: {e}"))?
        .next()
        .ok_or_else(|| format!("resolve {connect}: no address"))?;
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let _ = stream.set_nodelay(true);
    let key = key_from_seed(&seed);

    let mut join = Envelope::new("join", run_id, 0, node, 1, json!({"node": node}));
    join.sign(&key);
    write_frame(&mut stream, &join).map_err(|e| format!("join: {e}"))?;

    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
    let mut reader = crate::mesh::wire::FrameReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut nonce = 2u64;
    let mut welcomed = false;
    // Heartbeats prove the process is alive, not merely connected: a stopped
    // worker keeps its socket, so the server would otherwise see a healthy peer
    // forever. The interval matches the server's table (500 ms, expiry 3×).
    let mut last_beat = Instant::now();
    let mut heartbeat_nonce = 1u64;
    let beat_every = Duration::from_millis(500);
    loop {
        if welcomed && last_beat.elapsed() >= beat_every {
            heartbeat_nonce += 1;
            let mut hb = Envelope::new(
                HEARTBEAT,
                run_id,
                0,
                node,
                heartbeat_nonce,
                json!({}),
            );
            hb.sign(&key);
            write_frame(&mut stream, &hb).map_err(|e| format!("heartbeat: {e}"))?;
            last_beat = Instant::now();
        }
        let env = match reader.next() {
            Ok(Some(e)) => e,
            Ok(None) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return if welcomed {
                    Ok(())
                } else {
                    Err("join refused or server closed before welcome".to_string())
                }
            }
            // SIGSTOP/SIGCONT interrupt a blocking read with EINTR. Treating
            // that as failure killed the worker the moment it was resumed, and
            // the server then saw a closed peer instead of a returning one.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read: {e}")),
        };
        if env.kind == "refused" {
            return Err(format!(
                "join refused: {}",
                env.payload["reason"].as_str().unwrap_or("no reason given")
            ));
        }
        if env.kind == "welcome" {
            welcomed = true;
            continue;
        }
        if env.kind != "assign" {
            continue;
        }
        let task = env.payload["task"].as_str().unwrap_or_default().to_string();
        let func = env.payload["func"].as_str().unwrap_or_default().to_string();
        let wave = env.payload["seed"].as_u64().unwrap_or(0);
        let epoch = env.payload["epoch"].as_u64().unwrap_or(0);
        let task_seed = env.payload["task_seed"].as_u64().unwrap_or(0);

        if let Some(ms) = func.strip_prefix("sleep:") {
            if let Ok(ms) = ms.parse::<u64>() {
                thread::sleep(Duration::from_millis(ms));
            }
        }
        let hash = task_result_hash(&func, task_seed, wave, &task);

        nonce += 1;
        let mut result = Envelope::new(
            "result",
            run_id,
            env.wave,
            node,
            nonce,
            json!({"task": task, "hash": hash, "epoch": epoch}),
        );
        result.sign(&key);
        write_frame(&mut stream, &result).map_err(|e| format!("result: {e}"))?;
    }
}

/// The value a task produces. Deterministic in its inputs only — no clock, no
/// node identity — which is what makes the checkpoint comparable across runs.
pub fn task_result_hash(func: &str, task_seed: u64, wave: u64, task: &str) -> String {
    blake3::hash(format!("{func}|{task_seed}|{wave}|{task}").as_bytes())
        .to_hex()
        .to_string()
}

/// Local reference run, used by tests to prove a remote run commits the same
/// checkpoint. Uses the same task_result_hash and checkpoint_hash, so a
/// difference is a scheduling divergence, not a hashing one.
pub fn local_checkpoints(tasks: &[Task], mesh_seed: u64) -> Result<Vec<String>, String> {
    let waves = mesh_plan(tasks).map_err(|e| format!("plan: {e}"))?;
    let mut out = Vec::new();
    for (i, wave) in waves.iter().enumerate() {
        let wave_seed = crate::mesh::wave_seed(mesh_seed, i);
        let mut results: Vec<(String, String)> = wave
            .tasks
            .iter()
            .map(|t| {
                (
                    t.id.clone(),
                    task_result_hash(&t.func, crate::mesh::task_seed(mesh_seed, i, &t.id, 1), wave_seed, &t.id),
                )
            })
            .collect();
        results.sort();
        out.push(checkpoint_hash(&results));
    }
    Ok(out)
}

/// Silence an unused-import warning if the write trait is only used indirectly.
#[allow(dead_code)]
fn _assert_write<W: Write>(_: W) {}

#[allow(dead_code)]
fn _unused_try_recv(r: &Receiver<Envelope>) {
    let _ = matches!(r.try_recv(), Err(TryRecvError::Empty));
}
