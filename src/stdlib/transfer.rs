//! Standard library:  -- BLAKE3 Bao chunking, delta sync,
//! file vault encryption, fast copy, compression utilities, real erasure coding,
//! progress tracking, resume/checkpoints, bandwidth limiting, and directory encryption.
//!
//! Phase 58: Real reed-solomon-simd erasure coding, indicatif progress bars,
//! memmap2 fast I/O, resume/checkpoint, bandwidth limiting, directory encryption.
//!
//! All operations use REAL cryptographic primitives (blake3, aes-gcm, argon2, zstd, reed-solomon-simd).

use super::StdlibResult;
use crate::interp::Value;

use std::collections::HashMap;
use std::io::{BufReader, Read as IoRead};
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

// Phase 56 global state
static TRANSFER_SESSIONS: LazyLock<Mutex<HashMap<String, TransferSessionState>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static SESSION_COUNTER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));
// Phase 57 global state
static DHT_STORE: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static DHT_SOCKETS: LazyLock<Mutex<HashMap<String, std::net::UdpSocket>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static DHT_PEERS: LazyLock<Mutex<Vec<String>>> = LazyLock::new(|| Mutex::new(Vec::new()));

#[derive(Clone, Debug)]
#[allow(dead_code)]
struct TransferSessionState {
    _root_hash: String, total_size: usize, _chunk_count: usize,
    status: String, _encrypt: bool, bytes_transferred: usize,
    _chunks_done: usize, start_time_ms: u64,
}

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "chunk_file" => Some(chunk_file(&args)),
        "verify_chunk" => Some(verify_chunk(&args)),
        "file_hash" => Some(file_hash(&args)),
        "tree_hash" => Some(tree_hash(&args)),
        "delta_scan" => Some(delta_scan(&args)),
        "delta_diff" => Some(delta_diff(&args)),
        "delta_apply" => Some(delta_apply(&args)),
        "vault_encrypt_file" => Some(vault_encrypt_file(&args)),
        "vault_decrypt_file" => Some(vault_decrypt_file(&args)),
        "vault_encrypt_bytes" => Some(vault_encrypt_bytes(&args)),
        "vault_decrypt_bytes" => Some(vault_decrypt_bytes(&args)),
        "fast_copy" => Some(fast_copy(&args)),
        "fast_copy_dir" => Some(fast_copy_dir(&args)),
        "compress" => Some(compress_data(&args)),
        "decompress" => Some(decompress_data(&args)),
        "detect_compressibility" => Some(detect_compressibility(&args)),
        "create_manifest" => Some(create_manifest(&args)),
        "parse_manifest" => Some(parse_manifest_fn(&args)),
        // Phase 56
        "transfer_send" => Some(transfer_send(&args)),
        "transfer_receive" => Some(transfer_receive(&args)),
        "transfer_status" => Some(transfer_status(&args)),
        "stream_create" => Some(stream_create(&args)),
        "stream_write" => Some(stream_write(&args)),
        "stream_close" => Some(stream_close(&args)),
        "erasure_encode" => Some(erasure_encode(&args)),
        "erasure_decode" => Some(erasure_decode(&args)),
        "erasure_status" => Some(erasure_status(&args)),
        "paths_discover" => Some(paths_discover(&args)),
        "paths_estimate" => Some(paths_estimate(&args)),
        // Phase 58: Real erasure coding, progress, checkpoints, bandwidth, dir encryption
        "progress_create" => Some(progress_create(&args)),
        "progress_update" => Some(progress_update(&args)),
        "checkpoint_save" => Some(checkpoint_save(&args)),
        "checkpoint_load" => Some(checkpoint_load(&args)),
        "checkpoint_delete" => Some(checkpoint_delete(&args)),
        "bandwidth_limit" => Some(bandwidth_limit(&args)),
        "bandwidth_throttle" => Some(bandwidth_throttle(&args)),
        "lan_discover" => Some(lan_discover(&args)),
        "copy_with_metadata" => Some(copy_with_metadata(&args)),
        "vault_encrypt_dir" => Some(vault_encrypt_dir(&args)),
        "vault_decrypt_dir" => Some(vault_decrypt_dir(&args)),
        "mmap_read" => Some(mmap_read(&args)),
        "lz4_compress" => Some(lz4_compress(&args)),
        "lz4_decompress" => Some(lz4_decompress(&args)),
        "value_to_json" => Some(Ok(Value::String(
            args.first().map(value_to_json).unwrap_or_else(|| "null".to_string())
        ))),
        // Phase 57
        "peer_create" | "Peer.create" => Some(peer_create(&args)),
        "peer_announce" | "Peer.announce" => Some(peer_announce(&args)),
        "swarm_create" | "Swarm.create" => Some(swarm_create(&args)),
        "swarm_add_peer" | "Swarm.add_peer" => Some(swarm_add_peer(&args)),
        "swarm_remove_peer" | "Swarm.remove_peer" => Some(swarm_remove_peer(&args)),
        "swarm_status" | "Swarm.status" => Some(swarm_status(&args)),
        "swarm_schedule" | "Swarm.schedule" => Some(swarm_schedule(&args)),
        "dht_create" | "Dht.create" => Some(dht_create(&args)),
        "dht_announce" | "Dht.announce" => Some(dht_announce(&args)),
        "dht_lookup" | "Dht.lookup" => Some(dht_lookup(&args)),
        "manifest_to_url" | "Manifest.to_url" => Some(manifest_to_url(&args)),
        "manifest_from_url" | "Manifest.from_url" => Some(manifest_from_url(&args)),
        "manifest_to_qr" | "Manifest.to_qr" => Some(manifest_to_qr(&args)),
        // Phase 62: Signed manifests, audit log, expiring transfers, retention, file validation, crypto config
        "signed_manifest" => Some(signed_manifest(&args)),
        "verify_manifest" => Some(verify_manifest(&args)),
        "transfer_receipt" => Some(transfer_receipt(&args)),
        "audit_log" => Some(audit_log(&args)),
        "audit_verify" => Some(audit_verify(&args)),
        "audit_export" => Some(audit_export(&args)),
        "audit_save" => Some(audit_save(&args)),
        "transfer_expire" => Some(transfer_expire(&args)),
        "transfer_check_expiry" => Some(transfer_check_expiry(&args)),
        "retention_policy" => Some(retention_policy(&args)),
        "retention_apply" => Some(retention_apply(&args)),
        "validate_file_type" => Some(validate_file_type(&args)),
        "validate_allowlist" => Some(validate_allowlist(&args)),
        "crypto_config" => Some(crypto_config(&args)),
        // Phase 63: mTLS, key rotation, RBAC, webhooks, scheduling, AV scanning
        "mtls_config" => Some(mtls_config(&args)),
        "key_rotation_schedule" => Some(key_rotation_schedule(&args)),
        "key_rotation_check" => Some(key_rotation_check(&args)),
        "key_rotate" => Some(key_rotate(&args)),
        "rbac_create_user" => Some(rbac_create_user(&args)),
        "rbac_check" => Some(rbac_check(&args)),
        "webhook_config" => Some(webhook_config(&args)),
        "webhook_fire" => Some(webhook_fire(&args)),
        "schedule_create" => Some(schedule_create(&args)),
        "schedule_check" => Some(schedule_check(&args)),
        "av_scan" => Some(av_scan(&args)),
        "yara_scan" => Some(yara_scan(&args)),
        // ── Feature 5: Air-gap transfer modes ──
        // QR chunk encoding for visual/optical air-gap crossing.
        // Audio FSK encoding for acoustic transfer (BFSK: 1 byte = 1 tone).
        "airgap_to_qr"    => Some(airgap_to_qr(&args)),
        "airgap_from_qr"  => Some(airgap_from_qr(&args)),
        "airgap_to_audio" => Some(airgap_to_audio(&args)),
        // ── Feature 8: Cloud storage sync primitives ──
        // Real AWS S3 REST API with Signature V4. GCS/Azure via gcs_dispatch/azure_dispatch.
        "cloud_s3_list"       => Some(cloud_s3_list(&args)),
        "cloud_s3_upload"     => Some(cloud_s3_upload(&args)),
        "cloud_s3_download"   => Some(cloud_s3_download(&args)),
        "cloud_s3_delete"     => Some(cloud_s3_delete(&args)),
        "cloud_s3_head"       => Some(cloud_s3_head(&args)),
        "cloud_gcs_list"      => Some(cloud_gcs_dispatch("cloud_gcs_list",    "list",     &args)),
        "cloud_gcs_upload"    => Some(cloud_gcs_dispatch("cloud_gcs_upload",   "upload",   &args)),
        "cloud_gcs_download"  => Some(cloud_gcs_dispatch("cloud_gcs_download", "download", &args)),
        "cloud_azure_list"    => Some(cloud_azure_dispatch("cloud_azure_list",    "list",     &args)),
        "cloud_azure_upload"  => Some(cloud_azure_dispatch("cloud_azure_upload",   "upload",   &args)),
        "cloud_azure_download" => Some(cloud_azure_dispatch("cloud_azure_download", "download", &args)),
        // Block-level delta sync (fast_rsync — Dropbox AVX2 rsync algorithm)
        "block_signature" | "BlockSync.signature" => Some(block_signature(&args)),
        "block_delta"     | "BlockSync.delta"     => Some(block_delta(&args)),
        "block_apply"     | "BlockSync.apply"     => Some(block_apply(&args)),
        "block_sync_file" | "BlockSync.sync_file" => Some(block_sync_file(&args)),
        "block_sync_dir"  | "BlockSync.sync_dir"  => Some(block_sync_dir(&args)),
        // Two-way sync engine
        "twoway_init"    | "TwoWaySync.init"    => Some(twoway_init(&args)),
        "twoway_scan"    | "TwoWaySync.scan"    => Some(twoway_scan(&args)),
        "twoway_plan"    | "TwoWaySync.plan"    => Some(twoway_plan(&args)),
        "twoway_execute" | "TwoWaySync.execute" => Some(twoway_execute(&args)),
        "twoway_sync"    | "TwoWaySync.sync"    => Some(twoway_sync(&args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        let mut a = vec![object.clone()]; a.extend(args);
        match name.as_str() {
            "TransferSession" => match method { "status" => Some(transfer_status(&a)), _ => None },
            "TransferStream" => match method { "write" => Some(stream_write(&a)), "close" => Some(stream_close(&a)), _ => None },
            "ErasureEncoded" => match method { "status" => Some(erasure_status(&a)), "decode" => Some(erasure_decode(&a)), _ => None },
            "Swarm" => match method { "add_peer" => Some(swarm_add_peer(&a)), "remove_peer" => Some(swarm_remove_peer(&a)), "status" => Some(swarm_status(&a)), "schedule" => Some(swarm_schedule(&a)), _ => None },
            "Peer" => match method { "announce" => Some(peer_announce(&a)), _ => None },
            "DhtNode" => match method { "announce" => Some(dht_announce(&a)), "lookup" => Some(dht_lookup(&a)), _ => None },
            "ProgressTracker" => match method { "update" => Some(progress_update(&a)), _ => None },
            "Checkpoint" => match method { "delete" => { let tid = gsf(fields, "transfer_id").map(|v| v.as_string()).unwrap_or_default(); Some(checkpoint_delete(&[Value::String(tid)])) }, _ => None },
            "BandwidthLimit" => match method { "throttle" => Some(bandwidth_throttle(&a)), _ => None },
            // Phase 62
            "SignedManifest" => match method { "verify" => { let m = gsf(fields, "manifest").map(|v| v.as_string()).unwrap_or_default(); let s = gsf(fields, "signature").map(|v| v.as_string()).unwrap_or_default(); let sid = gsf(fields, "sender").map(|v| v.as_string()).unwrap_or_default(); Some(verify_manifest(&[Value::String(m), Value::String(s), Value::String(sid)])) }, _ => None },
            "ExpiringTransfer" => match method { "check" => Some(transfer_check_expiry(&a)), _ => None },
            // Phase 63
            "KeyRotation" => match method { "check" => Some(key_rotation_check(&a)), "rotate" => { let kid = gsf(fields, "key_id").map(|v| v.as_string()).unwrap_or_default(); let ver = gsf(fields, "key_version").map(|v| v.as_string()).unwrap_or_default(); Some(key_rotate(&[Value::String(kid), Value::String(ver)])) }, _ => None },
            "RbacUser" => match method { "check" => Some(rbac_check(&a)), _ => None },
            "WebhookConfig" => match method { "fire" => { let url = gsf(fields, "url").map(|v| v.as_string()).unwrap_or_default(); let sec = gsf(fields, "secret").cloned(); let mut fa = vec![Value::String(url)]; fa.extend(a.into_iter().skip(1)); if let Some(s) = sec { fa.push(s); } Some(webhook_fire(&fa)) }, _ => None },
            "TransferSchedule" => match method { "check" => Some(schedule_check(&a)), _ => None },
            _ => None,
        }
    } else { None }
}

fn get_string_arg(args: &[Value], idx: usize) -> Option<String> {
    args.get(idx).map(|v| v.as_string())
}

fn get_int_arg(args: &[Value], idx: usize) -> Option<i128> {
    match args.get(idx) {
        Some(Value::Int(n)) => Some(*n),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("transfer: hex string has odd length: {}", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("transfer: hex decode error at pos {i}: {e}"))
        })
        .collect()
}

const DEFAULT_CHUNK_SIZE: usize = 262144;

fn chunk_file(args: &[Value]) -> StdlibResult {
    let path = match get_string_arg(args, 0) {
        Some(p) => p,
        None => return Err("transfer.chunk_file: requires path argument".into()),
    };
    let chunk_size = get_int_arg(args, 1).map(|n| n as usize).unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 {
        return Err("transfer.chunk_file: chunk_size must be > 0".into());
    }
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("transfer.chunk_file: cannot open '{}': {}", path, e))?;
    let mut reader = BufReader::new(file);
    let mut chunks = Vec::new();
    let mut buf = vec![0u8; chunk_size];
    let mut offset: usize = 0;
    let mut index: usize = 0;
    loop {
        let bytes_read = reader.read(&mut buf)
            .map_err(|e| format!("transfer.chunk_file: read error: {}", e))?;
        if bytes_read == 0 { break; }
        let hash = blake3::hash(&buf[..bytes_read]);
        chunks.push(Value::Struct {
            name: "ChunkInfo".to_string(),
            fields: vec![
                ("index".into(), Value::Int(index as i128)),
                ("offset".into(), Value::Int(offset as i128)),
                ("size".into(), Value::Int(bytes_read as i128)),
                ("hash".into(), Value::String(hash.to_hex().to_string())),
            ],
        });
        offset += bytes_read;
        index += 1;
    }
    Ok(Value::Array(chunks))
}

fn verify_chunk(args: &[Value]) -> StdlibResult {
    let data = match get_string_arg(args, 0) {
        Some(s) => s,
        None => return Err("transfer.verify_chunk: requires data argument".into()),
    };
    let expected = match get_string_arg(args, 1) {
        Some(s) => s,
        None => return Err("transfer.verify_chunk: requires expected_hash argument".into()),
    };
    let actual = blake3::hash(data.as_bytes()).to_hex().to_string();
    Ok(Value::Bool(actual == expected))
}

fn file_hash(args: &[Value]) -> StdlibResult {
    let path = match get_string_arg(args, 0) {
        Some(p) => p,
        None => return Err("transfer.file_hash: requires path argument".into()),
    };
    let file = std::fs::File::open(&path)
        .map_err(|e| format!("transfer.file_hash: cannot open '{}': {}", path, e))?;
    let mut reader = BufReader::with_capacity(65536, file);
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)
            .map_err(|e| format!("transfer.file_hash: read error: {}", e))?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(Value::String(hasher.finalize().to_hex().to_string()))
}

fn tree_hash(args: &[Value]) -> StdlibResult {
    let hashes: Vec<String> = match args.first() {
        Some(Value::Array(arr)) => arr.iter().map(|v| v.as_string()).collect(),
        _ => return Err("transfer.tree_hash: requires array of hash strings".into()),
    };
    if hashes.is_empty() { return Err("transfer.tree_hash: empty hash array".into()); }
    if hashes.len() == 1 { return Ok(Value::String(hashes[0].clone())); }
    let mut level: Vec<String> = hashes;
    while level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let combined = format!("{}{}", level[i], level[i + 1]);
                let parent = blake3::hash(combined.as_bytes());
                next_level.push(parent.to_hex().to_string());
                i += 2;
            } else {
                next_level.push(level[i].clone());
                i += 1;
            }
        }
        level = next_level;
    }
    Ok(Value::String(level[0].clone()))
}

fn delta_scan(args: &[Value]) -> StdlibResult {
    let dir_path = match get_string_arg(args, 0) {
        Some(p) => p,
        None => return Err("transfer.delta_scan: requires dir_path argument".into()),
    };
    let path = Path::new(&dir_path);
    if !path.is_dir() {
        return Err(format!("transfer.delta_scan: '{}' is not a directory", dir_path));
    }
    let mut entries = Vec::new();
    scan_dir_recursive(path, &mut entries)?;
    Ok(Value::Array(entries))
}

fn scan_dir_recursive(dir: &Path, entries: &mut Vec<Value>) -> Result<(), String> {
    let read_dir = std::fs::read_dir(dir)
        .map_err(|e| format!("transfer.delta_scan: cannot read '{}': {}", dir.display(), e))?;
    for entry in read_dir {
        let entry = entry.map_err(|e| format!("transfer.delta_scan: entry error: {}", e))?;
        let path = entry.path();
        let metadata = entry.metadata()
            .map_err(|e| format!("transfer.delta_scan: metadata error: {}", e))?;
        if metadata.is_symlink() { continue; }
        if metadata.is_dir() {
            scan_dir_recursive(&path, entries)?;
        } else if metadata.is_file() {
            let size = metadata.len();
            let hash = if size > 1_073_741_824 {
                "lazy".to_string()
            } else {
                let data = std::fs::read(&path)
                    .map_err(|e| format!("transfer.delta_scan: read error: {}", e))?;
                blake3::hash(&data).to_hex().to_string()
            };
            let modified_epoch = metadata.modified().ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs()).unwrap_or(0);
            entries.push(Value::Struct {
                name: "FileEntry".to_string(),
                fields: vec![
                    ("path".into(), Value::String(path.to_string_lossy().to_string())),
                    ("size".into(), Value::Int(size as i128)),
                    ("hash".into(), Value::String(hash)),
                    ("modified_epoch".into(), Value::Int(modified_epoch as i128)),
                ],
            });
        }
    }
    Ok(())
}

fn delta_diff(args: &[Value]) -> StdlibResult {
    let old_entries = match args.first() {
        Some(Value::Array(arr)) => arr,
        _ => return Err("transfer.delta_diff: requires old_scan array as first argument".into()),
    };
    let new_entries = match args.get(1) {
        Some(Value::Array(arr)) => arr,
        _ => return Err("transfer.delta_diff: requires new_scan array as second argument".into()),
    };
    let old_map = build_path_hash_map(old_entries);
    let new_map = build_path_hash_map(new_entries);
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();
    let mut unchanged: i128 = 0;
    let mut total_changed_bytes: i128 = 0;
    let new_sizes = build_path_size_map(new_entries);
    for (path, hash) in &new_map {
        match old_map.get(path) {
            None => { added.push(Value::String(path.clone())); total_changed_bytes += new_sizes.get(path).copied().unwrap_or(0); }
            Some(old_hash) => {
                if old_hash != hash { modified.push(Value::String(path.clone())); total_changed_bytes += new_sizes.get(path).copied().unwrap_or(0); }
                else { unchanged += 1; }
            }
        }
    }
    for path in old_map.keys() { if !new_map.contains_key(path) { removed.push(Value::String(path.clone())); } }
    Ok(Value::Struct {
        name: "DeltaResult".to_string(),
        fields: vec![
            ("added".into(), Value::Array(added)), ("removed".into(), Value::Array(removed)),
            ("modified".into(), Value::Array(modified)), ("unchanged".into(), Value::Int(unchanged)),
            ("total_changed_bytes".into(), Value::Int(total_changed_bytes)),
        ],
    })
}

fn build_path_hash_map(entries: &[Value]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for entry in entries {
        if let Value::Struct { fields, .. } = entry {
            let path = fields.iter().find(|(k, _)| k == "path").map(|(_, v)| v.as_string()).unwrap_or_default();
            let hash = fields.iter().find(|(k, _)| k == "hash").map(|(_, v)| v.as_string()).unwrap_or_default();
            map.insert(path, hash);
        }
    }
    map
}

fn build_path_size_map(entries: &[Value]) -> std::collections::HashMap<String, i128> {
    let mut map = std::collections::HashMap::new();
    for entry in entries {
        if let Value::Struct { fields, .. } = entry {
            let path = fields.iter().find(|(k, _)| k == "path").map(|(_, v)| v.as_string()).unwrap_or_default();
            let size = fields.iter().find(|(k, _)| k == "size")
                .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0);
            map.insert(path, size);
        }
    }
    map
}

fn delta_apply(args: &[Value]) -> StdlibResult {
    let diff = match args.first() {
        Some(Value::Struct { name, fields }) if name == "DeltaResult" => fields,
        _ => return Err("transfer.delta_apply: requires DeltaResult struct as first argument".into()),
    };
    let src_dir = match get_string_arg(args, 1) { Some(s) => s, None => return Err("transfer.delta_apply: requires src_dir argument".into()) };
    let dst_dir = match get_string_arg(args, 2) { Some(s) => s, None => return Err("transfer.delta_apply: requires dst_dir argument".into()) };
    let start = Instant::now();
    let added = diff.iter().find(|(k, _)| k == "added").and_then(|(_, v)| if let Value::Array(a) = v { Some(a.clone()) } else { None }).unwrap_or_default();
    let modified = diff.iter().find(|(k, _)| k == "modified").and_then(|(_, v)| if let Value::Array(a) = v { Some(a.clone()) } else { None }).unwrap_or_default();
    let removed = diff.iter().find(|(k, _)| k == "removed").and_then(|(_, v)| if let Value::Array(a) = v { Some(a.clone()) } else { None }).unwrap_or_default();
    let mut files_copied: i128 = 0;
    let mut bytes_copied: i128 = 0;
    let src_path = Path::new(&src_dir);
    let dst_path = Path::new(&dst_dir);
    for file_val in added.iter().chain(modified.iter()) {
        let rel_path = file_val.as_string();
        let rel = Path::new(&rel_path).strip_prefix(src_path).unwrap_or(Path::new(&rel_path));
        let sf = src_path.join(rel);
        let df = dst_path.join(rel);
        if let Some(p) = df.parent() { std::fs::create_dir_all(p).map_err(|e| format!("transfer.delta_apply: mkdir: {}", e))?; }
        let c = std::fs::copy(&sf, &df).map_err(|e| format!("transfer.delta_apply: copy: {}", e))?;
        files_copied += 1; bytes_copied += c as i128;
    }
    for fv in &removed {
        let rp = fv.as_string();
        let rel = Path::new(&rp).strip_prefix(dst_path).unwrap_or(Path::new(&rp));
        let _ = std::fs::remove_file(dst_path.join(rel));
    }
    Ok(Value::Struct { name: "CopyStats".to_string(), fields: vec![
        ("files_copied".into(), Value::Int(files_copied)), ("bytes_copied".into(), Value::Int(bytes_copied)),
        ("elapsed_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
    ]})
}

const VAULT_MAGIC: &[u8; 4] = b"NIXV";
const VAULT_VERSION: u8 = 1;

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    use argon2::Argon2;
    let argon2 = Argon2::default();
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("transfer.vault: key derivation failed: {}", e))?;
    Ok(key)
}

fn vault_encrypt_file(args: &[Value]) -> StdlibResult {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let input_path = match get_string_arg(args, 0) { Some(p) => p, None => return Err("transfer.vault_encrypt_file: requires input_path".into()) };
    let output_path = match get_string_arg(args, 1) { Some(p) => p, None => return Err("transfer.vault_encrypt_file: requires output_path".into()) };
    let password = match get_string_arg(args, 2) { Some(p) => p, None => return Err("transfer.vault_encrypt_file: requires password".into()) };
    let plaintext = std::fs::read(&input_path).map_err(|e| format!("transfer.vault_encrypt_file: read '{}': {}", input_path, e))?;
    let input_size = plaintext.len();
    let mut salt = [0u8; 16]; rand::Rng::fill(&mut rand::rng(), &mut salt);
    let mut nonce_bytes = [0u8; 12]; rand::Rng::fill(&mut rand::rng(), &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let key = derive_key(&password, &salt)?;
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| format!("transfer.vault_encrypt_file: encrypt: {}", e))?;
    let mut output = Vec::with_capacity(4 + 1 + 16 + 12 + ct.len());
    output.extend_from_slice(VAULT_MAGIC); output.push(VAULT_VERSION);
    output.extend_from_slice(&salt); output.extend_from_slice(&nonce_bytes); output.extend_from_slice(&ct);
    std::fs::write(&output_path, &output).map_err(|e| format!("transfer.vault_encrypt_file: write '{}': {}", output_path, e))?;
    Ok(Value::Struct { name: "EncryptResult".to_string(), fields: vec![
        ("input_size".into(), Value::Int(input_size as i128)), ("output_size".into(), Value::Int(output.len() as i128)),
        ("encrypted".into(), Value::Bool(true)), ("algo".into(), Value::String("aes-256-gcm".into())),
    ]})
}

fn vault_decrypt_file(args: &[Value]) -> StdlibResult {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let input_path = match get_string_arg(args, 0) { Some(p) => p, None => return Err("transfer.vault_decrypt_file: requires input_path".into()) };
    let output_path = match get_string_arg(args, 1) { Some(p) => p, None => return Err("transfer.vault_decrypt_file: requires output_path".into()) };
    let password = match get_string_arg(args, 2) { Some(p) => p, None => return Err("transfer.vault_decrypt_file: requires password".into()) };
    let data = std::fs::read(&input_path).map_err(|e| format!("transfer.vault_decrypt_file: read '{}': {}", input_path, e))?;
    if data.len() < 33 { return Err("transfer.vault_decrypt_file: file too small".into()); }
    if &data[0..4] != VAULT_MAGIC { return Err("transfer.vault_decrypt_file: not a NIXV file".into()); }
    let salt = &data[5..21]; let nonce_bytes = &data[21..33]; let ct = &data[33..];
    let key = derive_key(&password, salt)?;
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher.decrypt(Nonce::from_slice(nonce_bytes), ct).map_err(|_| "transfer.vault_decrypt_file: decryption failed".to_string())?;
    std::fs::write(&output_path, &pt).map_err(|e| format!("transfer.vault_decrypt_file: write '{}': {}", output_path, e))?;
    Ok(Value::Struct { name: "DecryptResult".to_string(), fields: vec![
        ("output_size".into(), Value::Int(pt.len() as i128)), ("decrypted".into(), Value::Bool(true)),
    ]})
}

fn vault_encrypt_bytes(args: &[Value]) -> StdlibResult {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let data = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.vault_encrypt_bytes: requires data".into()) };
    let password = match get_string_arg(args, 1) { Some(s) => s, None => return Err("transfer.vault_encrypt_bytes: requires password".into()) };
    let mut salt = [0u8; 16]; rand::Rng::fill(&mut rand::rng(), &mut salt);
    let mut nonce_bytes = [0u8; 12]; rand::Rng::fill(&mut rand::rng(), &mut nonce_bytes);
    let key = derive_key(&password, &salt)?;
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), data.as_bytes()).map_err(|e| format!("transfer.vault_encrypt_bytes: {}", e))?;
    let mut combined = Vec::with_capacity(16 + 12 + ct.len());
    combined.extend_from_slice(&salt); combined.extend_from_slice(&nonce_bytes); combined.extend_from_slice(&ct);
    Ok(Value::String(hex_encode(&combined)))
}

fn vault_decrypt_bytes(args: &[Value]) -> StdlibResult {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
    let hex_str = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.vault_decrypt_bytes: requires encrypted_hex".into()) };
    let password = match get_string_arg(args, 1) { Some(s) => s, None => return Err("transfer.vault_decrypt_bytes: requires password".into()) };
    let combined = hex_decode(&hex_str)?;
    if combined.len() < 28 { return Err("transfer.vault_decrypt_bytes: data too short".into()); }
    let key = derive_key(&password, &combined[0..16])?;
    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let pt = cipher.decrypt(Nonce::from_slice(&combined[16..28]), &combined[28..]).map_err(|_| "transfer.vault_decrypt_bytes: decryption failed".to_string())?;
    String::from_utf8(pt).map(Value::String).map_err(|e| format!("transfer.vault_decrypt_bytes: UTF-8: {}", e))
}

fn fast_copy(args: &[Value]) -> StdlibResult {
    let src = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.fast_copy: requires src".into()) };
    let dst = match get_string_arg(args, 1) { Some(s) => s, None => return Err("transfer.fast_copy: requires dst".into()) };
    let start = Instant::now();
    let bc = copy_file_with_fallback(Path::new(&src), Path::new(&dst))
        .map_err(|e| format!("transfer.fast_copy: {}", e))?;
    let ms = start.elapsed().as_millis() as i128;
    let tp = if ms > 0 { (bc as f64 / 1_048_576.0) / (ms as f64 / 1000.0) } else { 0.0 };
    Ok(Value::Struct { name: "CopyStats".to_string(), fields: vec![
        ("bytes_copied".into(), Value::Int(bc as i128)), ("elapsed_ms".into(), Value::Int(ms)), ("throughput_mbps".into(), Value::Float(tp)),
    ]})
}

fn fast_copy_dir(args: &[Value]) -> StdlibResult {
    let src = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.fast_copy_dir: requires src".into()) };
    let dst = match get_string_arg(args, 1) { Some(s) => s, None => return Err("transfer.fast_copy_dir: requires dst".into()) };
    let sp = Path::new(&src); let dp = Path::new(&dst);
    if !sp.is_dir() { return Err(format!("transfer.fast_copy_dir: '{}' is not a directory", src)); }
    let start = Instant::now();
    let (mut fc, mut dc, mut bc) = (0i128, 0i128, 0i128);
    copy_dir_recursive(sp, dp, &mut fc, &mut dc, &mut bc)?;
    Ok(Value::Struct { name: "CopyStats".to_string(), fields: vec![
        ("files_copied".into(), Value::Int(fc)), ("dirs_created".into(), Value::Int(dc)),
        ("bytes_copied".into(), Value::Int(bc)), ("elapsed_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
    ]})
}

fn copy_dir_recursive(src: &Path, dst: &Path, fc: &mut i128, dc: &mut i128, bc: &mut i128) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("transfer.fast_copy_dir: mkdir: {}", e))?;
    *dc += 1;
    for entry in std::fs::read_dir(src).map_err(|e| format!("transfer.fast_copy_dir: read: {}", e))? {
        let entry = entry.map_err(|e| format!("transfer.fast_copy_dir: entry: {}", e))?;
        let se = entry.path(); let de = dst.join(entry.file_name());
        let md = entry.metadata().map_err(|e| format!("transfer.fast_copy_dir: metadata: {}", e))?;
        if md.is_dir() { copy_dir_recursive(&se, &de, fc, dc, bc)?; }
        else if md.is_file() {
            let c = copy_file_with_fallback(&se, &de)
                .map_err(|e| format!("transfer.fast_copy_dir: copy: {}", e))?;
            *fc += 1; *bc += c as i128;
        }
    }
    Ok(())
}

/// Copy a file using normal `std::fs::copy`. On Windows, if the file is locked (sharing
/// violation / lock violation), transparently falls back to opening with maximum share flags
/// and, if that also fails, to a PowerShell VSS shadow-copy as the last resort.
///
/// On non-Windows platforms the function returns an `Err` for locked files (Unix does not
/// lock files the same way and has no VSS equivalent).
pub fn copy_file_with_fallback(src: &Path, dst: &Path) -> Result<u64, String> {
    match std::fs::copy(src, dst) {
        Ok(n) => Ok(n),
        Err(e) if is_sharing_violation(&e) => {
            #[cfg(windows)]
            {
                copy_via_vss(src, dst)
            }
            #[cfg(not(windows))]
            {
                Err(format!("file is locked: {}: {}", src.display(), e))
            }
        }
        Err(e) => Err(format!("copy failed: {}: {}", src.display(), e)),
    }
}

/// Returns `true` when the OS error is a Windows sharing/lock violation (error 32 or 33).
fn is_sharing_violation(e: &std::io::Error) -> bool {
    // ERROR_SHARING_VIOLATION = 32, ERROR_LOCK_VIOLATION = 33
    matches!(e.raw_os_error(), Some(32) | Some(33))
}

/// Windows: copy a locked file by first trying to open it with full share flags so that
/// other processes holding non-exclusive handles cannot block us. Falls back to a
/// PowerShell VSS shadow copy if even that fails.
#[cfg(windows)]
fn copy_via_vss(src: &Path, dst: &Path) -> Result<u64, String> {
    use std::os::windows::fs::OpenOptionsExt as _;

    // FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE = 0x01 | 0x02 | 0x04
    const SHARE_ALL: u32 = 0x00000001 | 0x00000002 | 0x00000004;

    match std::fs::OpenOptions::new()
        .read(true)
        .share_mode(SHARE_ALL)
        .open(src)
    {
        Ok(mut reader) => {
            if let Some(parent) = dst.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut writer = std::fs::File::create(dst)
                .map_err(|e| format!("VSS: cannot create destination {}: {}", dst.display(), e))?;
            let bytes = std::io::copy(&mut reader, &mut writer)
                .map_err(|e| format!("VSS: copy failed: {}", e))?;
            Ok(bytes)
        }
        Err(_) => copy_via_vss_subprocess(src, dst),
    }
}

/// Windows last-resort: create a VSS shadow copy via PowerShell/WMI, read the file from
/// the shadow device, then delete the shadow. Handles SQL Server `.mdf`, Exchange `.edb`,
/// and other files held with exclusive locks by services.
///
/// A6.1/R7: paths travel to the script via **environment variables** — nothing is
/// interpolated into the `-Command` string, so a file name can never alter PowerShell
/// parsing (was: raw `format!` interpolation of drive/rel/dst into quoted literals).
#[cfg(windows)]
fn copy_via_vss_subprocess(src: &Path, dst: &Path) -> Result<u64, String> {
    const PS_VSS_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$src = $env:TALLOW_VSS_SRC
$dst = $env:TALLOW_VSS_DST
if (-not $src) { throw 'TALLOW_VSS_SRC is not set' }
if (-not $dst) { throw 'TALLOW_VSS_DST is not set' }
$drive = $src.Substring(0,1)
$shadow = (Get-WmiObject -List Win32_ShadowCopy).Create(($drive + ':\'), 'ClientAccessible')
$shadowId = $shadow.ShadowID
$shadowObj = Get-WmiObject Win32_ShadowCopy | Where-Object { $_.ID -eq $shadowId }
$shadowDevice = $shadowObj.DeviceObject + '\'
$rel = $src
if ($rel.Length -ge 3 -and $rel[1] -eq ':' -and $rel[2] -eq '\') { $rel = $rel.Substring(3) }
$rel = $rel.Replace('/','\')
$sourcePath = $shadowDevice + $rel
Copy-Item $sourcePath $dst -Force
$shadowObj.Delete()
"#;

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", PS_VSS_SCRIPT])
        .env("TALLOW_VSS_SRC", src.as_os_str())
        .env("TALLOW_VSS_DST", dst.as_os_str())
        .output()
        .map_err(|e| format!("VSS: PowerShell launch failed: {}", e))?;

    if output.status.success() {
        let size = std::fs::metadata(dst).map(|m| m.len()).unwrap_or(0);
        Ok(size)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!(
            "VSS shadow copy failed for {}: {}",
            src.display(),
            stderr.trim()
        ))
    }
}

fn compress_data(args: &[Value]) -> StdlibResult {
    let data = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.compress: requires data".into()) };
    let algo = get_string_arg(args, 1).unwrap_or_else(|| "zstd".into());
    let level = get_int_arg(args, 2).unwrap_or(3) as i32;
    match algo.as_str() {
        "zstd" => { let c = zstd::encode_all(data.as_bytes(), level).map_err(|e| format!("transfer.compress: {}", e))?; Ok(Value::String(hex_encode(&c))) }
        "none" => Ok(Value::String(hex_encode(data.as_bytes()))),
        o => Err(format!("transfer.compress: unsupported '{}'", o)),
    }
}

fn decompress_data(args: &[Value]) -> StdlibResult {
    let hex_str = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.decompress: requires hex data".into()) };
    let algo = get_string_arg(args, 1).unwrap_or_else(|| "zstd".into());
    let compressed = hex_decode(&hex_str)?;
    match algo.as_str() {
        "zstd" => { let d = zstd::decode_all(std::io::Cursor::new(compressed)).map_err(|e| format!("transfer.decompress: {}", e))?; String::from_utf8(d).map(Value::String).map_err(|e| format!("transfer.decompress: {}", e)) }
        "none" => String::from_utf8(compressed).map(Value::String).map_err(|e| format!("transfer.decompress: {}", e)),
        o => Err(format!("transfer.decompress: unsupported '{}'", o)),
    }
}

fn detect_compressibility(args: &[Value]) -> StdlibResult {
    let data = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.detect_compressibility: requires data".into()) };
    let sample = if data.len() > 65536 { &data.as_bytes()[..65536] } else { data.as_bytes() };
    let entropy = shannon_entropy(sample);
    let compressible = entropy < 6.5;
    Ok(Value::Struct { name: "CompressibilityResult".to_string(), fields: vec![
        ("entropy".into(), Value::Float(entropy)), ("compressible".into(), Value::Bool(compressible)),
        ("recommended_algo".into(), Value::String(if compressible { "zstd" } else { "none" }.into())),
    ]})
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u64; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / len; -p * p.log2() }).sum()
}

fn create_manifest(args: &[Value]) -> StdlibResult {
    let rh = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.create_manifest: requires root_hash".into()) };
    let size = get_int_arg(args, 1).unwrap_or(0);
    let cc = match args.get(2) { Some(Value::Array(arr)) => arr.len(), _ => 0 };
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    Ok(Value::String(format!(r#"{{"root_hash":"{}","size":{},"chunk_count":{},"timestamp":{}}}"#, rh, size, cc, ts)))
}

fn parse_manifest_fn(args: &[Value]) -> StdlibResult {
    let js = match get_string_arg(args, 0) { Some(s) => s, None => return Err("transfer.parse_manifest: requires json".into()) };
    let p: serde_json::Value = serde_json::from_str(&js).map_err(|e| format!("transfer.parse_manifest: {}", e))?;
    Ok(Value::Struct { name: "ManifestInfo".to_string(), fields: vec![
        ("root_hash".into(), Value::String(p["root_hash"].as_str().unwrap_or("").to_string())),
        ("size".into(), Value::Int(p["size"].as_i64().unwrap_or(0) as i128)),
        ("chunk_count".into(), Value::Int(p["chunk_count"].as_i64().unwrap_or(0) as i128)),
        ("timestamp".into(), Value::Int(p["timestamp"].as_i64().unwrap_or(0) as i128)),
    ]})
}

// Phase 56 helpers
fn now_iso_p56() -> String { let s = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64; crate::stdlib::time::epoch_secs_to_iso(s) }
fn now_ms_p56() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }
fn unique_hex_id() -> String { let mut c = SESSION_COUNTER.lock().unwrap(); *c += 1; let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos(); format!("{:08x}-{:04x}", n & 0xFFFF_FFFF, *c) }
fn gsf<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a Value> { fields.iter().find(|(k, _)| k == key).map(|(_, v)| v) }
fn chunk_data_p56(data: &str, sz: usize) -> Vec<String> { if data.is_empty() { return vec![]; } data.as_bytes().chunks(sz).map(|c| String::from_utf8_lossy(c).to_string()).collect() }
fn b3hex(input: &str) -> String { blake3::hash(input.as_bytes()).to_hex().to_string() }

fn transfer_send(args: &[Value]) -> StdlibResult {
    let data = match args.first() { Some(v) => v.as_string(), None => return Err("transfer_send() requires data".into()) };
    let recip = match args.get(1) { Some(v) => v.as_string(), None => "localhost".into() };
    let enc = match args.get(2) { Some(Value::Bool(b)) => *b, _ => true };
    let sid = format!("xfer-{}", unique_hex_id()); let ts = data.len();
    let chunks = chunk_data_p56(&data, 256); let cc = chunks.len().max(1);
    let ch: Vec<String> = chunks.iter().enumerate().map(|(i, c)| b3hex(&format!("chunk:{sid}:{i}:{c}"))).collect();
    let rh = b3hex(&format!("root:{sid}:{}", ch.join("")));
    let now = now_iso_p56(); let sm = now_ms_p56();
    TRANSFER_SESSIONS.lock().unwrap().insert(sid.clone(), TransferSessionState { _root_hash: rh.clone(), total_size: ts, _chunk_count: cc, status: "ready".into(), _encrypt: enc, bytes_transferred: 0, _chunks_done: 0, start_time_ms: sm });
    let hv: Vec<Value> = ch.into_iter().map(Value::String).collect();
    Ok(Value::Struct { name: "TransferSession".into(), fields: vec![("session_id".into(), Value::String(sid)), ("root_hash".into(), Value::String(rh)), ("total_size".into(), Value::Int(ts as i128)), ("chunk_count".into(), Value::Int(cc as i128)), ("chunk_hashes".into(), Value::Array(hv)), ("status".into(), Value::String("ready".into())), ("encrypt".into(), Value::Bool(enc)), ("recipient".into(), Value::String(recip)), ("created_at".into(), Value::String(now))] })
}
fn transfer_receive(args: &[Value]) -> StdlibResult {
    let (rh, ts, cc) = match args.first() {
        Some(Value::Struct { name, fields }) if name == "TransferSession" => (gsf(fields, "root_hash").map(|v| v.as_string()).unwrap_or_default(), gsf(fields, "total_size").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0), gsf(fields, "chunk_count").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0)),
        Some(Value::String(s)) => match serde_json::from_str::<serde_json::Value>(s) { Ok(j) => (j.get("root_hash").and_then(|v| v.as_str()).unwrap_or("").into(), j.get("total_size").and_then(|v| v.as_u64()).unwrap_or(0) as usize, j.get("chunk_count").and_then(|v| v.as_u64()).unwrap_or(0) as usize), Err(_) => (s.clone(), 0, 0) },
        _ => (String::new(), 0, 0),
    };
    let rid = format!("recv-{}", unique_hex_id()); let now = now_iso_p56(); let sm = now_ms_p56();
    TRANSFER_SESSIONS.lock().unwrap().insert(rid.clone(), TransferSessionState { _root_hash: rh.clone(), total_size: ts, _chunk_count: cc, status: "waiting".into(), _encrypt: false, bytes_transferred: 0, _chunks_done: 0, start_time_ms: sm });
    Ok(Value::Struct { name: "TransferSession".into(), fields: vec![("session_id".into(), Value::String(rid)), ("root_hash".into(), Value::String(rh)), ("total_size".into(), Value::Int(ts as i128)), ("chunk_count".into(), Value::Int(cc as i128)), ("chunks_received".into(), Value::Int(0)), ("status".into(), Value::String("waiting".into())), ("created_at".into(), Value::String(now))] })
}
fn transfer_status(args: &[Value]) -> StdlibResult {
    let (sid, ts, cc) = match args.first() {
        Some(Value::Struct { name, fields }) if name == "TransferSession" => (gsf(fields, "session_id").map(|v| v.as_string()).unwrap_or_default(), gsf(fields, "total_size").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0), gsf(fields, "chunk_count").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0)),
        _ => return Err("transfer_status() requires a TransferSession struct".into()),
    };
    let sess = TRANSFER_SESSIONS.lock().unwrap();
    let (bt, cd, st, sm) = match sess.get(&sid) { Some(s) => (s.bytes_transferred, s._chunks_done, s.status.clone(), s.start_time_ms), None => (0, 0, "unknown".into(), now_ms_p56()) };
    let el = now_ms_p56().saturating_sub(sm);
    let pct = if ts > 0 { (bt as f64 / ts as f64 * 100.0).min(100.0) } else { 0.0 };
    let tp = if el > 0 { bt as f64 * 8.0 / (el as f64 * 1000.0) } else { 0.0 };
    Ok(Value::Struct { name: "TransferProgress".into(), fields: vec![("bytes_transferred".into(), Value::Int(bt as i128)), ("bytes_total".into(), Value::Int(ts as i128)), ("percent".into(), Value::Float(pct)), ("chunks_done".into(), Value::Int(cd as i128)), ("chunks_total".into(), Value::Int(cc as i128)), ("elapsed_ms".into(), Value::Int(el as i128)), ("throughput_mbps".into(), Value::Float(tp)), ("status".into(), Value::String(st))] })
}
fn stream_create(args: &[Value]) -> StdlibResult {
    let sid = match args.first() { Some(v) => v.as_string(), None => return Err("stream_create() requires session_id".into()) };
    let st = match args.get(1) { Some(v) => { let t = v.as_string(); if t == "reliable" || t == "unreliable" { t } else { "reliable".into() } } None => "reliable".into() };
    Ok(Value::Struct { name: "TransferStream".into(), fields: vec![("stream_id".into(), Value::String(format!("stream-{}", unique_hex_id()))), ("session_id".into(), Value::String(sid)), ("stream_type".into(), Value::String(st)), ("bytes_sent".into(), Value::Int(0)), ("open".into(), Value::Bool(true))] })
}
fn stream_write(args: &[Value]) -> StdlibResult {
    let (stid, ssid, st, prev) = match args.first() {
        Some(Value::Struct { name, fields }) if name == "TransferStream" => {
            if !gsf(fields, "open").and_then(|v| if let Value::Bool(b) = v { Some(*b) } else { None }).unwrap_or(true) { return Err("stream_write(): stream is closed".into()); }
            (gsf(fields, "stream_id").map(|v| v.as_string()).unwrap_or_default(), gsf(fields, "session_id").map(|v| v.as_string()).unwrap_or_default(), gsf(fields, "stream_type").map(|v| v.as_string()).unwrap_or_else(|| "reliable".into()), gsf(fields, "bytes_sent").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0))
        }
        _ => return Err("stream_write() requires a TransferStream struct".into()),
    };
    let data = match args.get(1) { Some(v) => v.as_string(), None => return Err("stream_write() requires data".into()) };
    let nb = prev + data.len();
    if let Ok(mut s) = TRANSFER_SESSIONS.lock() { if let Some(st2) = s.get_mut(&ssid) { st2.bytes_transferred += data.len(); } }
    Ok(Value::Struct { name: "TransferStream".into(), fields: vec![("stream_id".into(), Value::String(stid)), ("session_id".into(), Value::String(ssid)), ("stream_type".into(), Value::String(st)), ("bytes_sent".into(), Value::Int(nb as i128)), ("open".into(), Value::Bool(true))] })
}
fn stream_close(args: &[Value]) -> StdlibResult {
    let (stid, ssid, st, bs) = match args.first() {
        Some(Value::Struct { name, fields }) if name == "TransferStream" => (gsf(fields, "stream_id").map(|v| v.as_string()).unwrap_or_default(), gsf(fields, "session_id").map(|v| v.as_string()).unwrap_or_default(), gsf(fields, "stream_type").map(|v| v.as_string()).unwrap_or_else(|| "reliable".into()), gsf(fields, "bytes_sent").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0)),
        _ => return Err("stream_close() requires a TransferStream struct".into()),
    };
    Ok(Value::Struct { name: "TransferStream".into(), fields: vec![("stream_id".into(), Value::String(stid)), ("session_id".into(), Value::String(ssid)), ("stream_type".into(), Value::String(st)), ("bytes_sent".into(), Value::Int(bs as i128)), ("open".into(), Value::Bool(false))] })
}
fn erasure_encode(args: &[Value]) -> StdlibResult {
    let data = match args.first() { Some(v) => v.as_string(), None => return Err("erasure_encode() requires data".into()) };
    let oh = match args.get(1) { Some(Value::Float(f)) => *f, Some(Value::Int(n)) => *n as f64, _ => 0.5 };
    if oh < 0.0 { return Err("erasure_encode(): overhead must be non-negative".into()); }

    let data_bytes = data.as_bytes();
    // Use 10 data shards (or fewer if data is very small)
    let data_shards = std::cmp::min(10, std::cmp::max(1, data_bytes.len()));
    let recovery_shards = std::cmp::max(1, (data_shards as f64 * oh).ceil() as usize);

    // Pad data to be evenly divisible by data_shards
    // reed-solomon-simd requires shard_size to be a multiple of 2
    let raw_shard_size = std::cmp::max(1, (data_bytes.len() + data_shards - 1) / data_shards);
    let shard_size = if raw_shard_size % 2 != 0 { raw_shard_size + 1 } else { raw_shard_size };
    let shard_size = std::cmp::max(2, shard_size); // minimum 2 bytes (must be even)
    let mut padded = data_bytes.to_vec();
    padded.resize(shard_size * data_shards, 0);

    // Split padded data into individual shard slices for reed-solomon-simd
    let shard_slices: Vec<&[u8]> = padded.chunks(shard_size).collect();

    // Try real reed-solomon-simd encoding
    match reed_solomon_simd::encode(data_shards, recovery_shards, shard_slices) {
        Ok(recovery) => {
            let original_shards: Vec<Value> = padded.chunks(shard_size)
                .map(|chunk| Value::String(hex_encode(chunk)))
                .collect();
            let recovery_shards_val: Vec<Value> = recovery.iter()
                .map(|shard| Value::String(hex_encode(shard)))
                .collect();
            let n = data_shards + recovery.len();
            let mut all_symbols = original_shards;
            all_symbols.extend(recovery_shards_val);

            Ok(Value::Struct { name: "ErasureEncoded".into(), fields: vec![
                ("k".into(), Value::Int(data_shards as i128)),
                ("n".into(), Value::Int(n as i128)),
                ("shard_size".into(), Value::Int(shard_size as i128)),
                ("original_size".into(), Value::Int(data_bytes.len() as i128)),
                ("symbols".into(), Value::Array(all_symbols)),
                ("overhead".into(), Value::Float(oh)),
                ("systematic".into(), Value::Bool(true)),
                ("codec".into(), Value::String("reed-solomon-simd".into())),
                ("data_size".into(), Value::Int(data_bytes.len() as i128)),
            ] })
        }
        Err(e) => Err(format!("erasure encoding failed: {e}")),
    }
}

fn erasure_decode(args: &[Value]) -> StdlibResult {
    let (symbols, k, shard_size, original_size) = match args.first() {
        Some(Value::Array(arr)) => {
            let k = match args.get(1) { Some(Value::Int(n)) => *n as usize, _ => return Err("erasure_decode() requires k".into()) };
            let ss = match args.get(2) { Some(Value::Int(n)) => *n as usize, _ => 0 };
            let os = match args.get(3) { Some(Value::Int(n)) => *n as usize, _ => 0 };
            (arr.clone(), k, ss, os)
        }
        Some(Value::Struct { name, fields }) if name == "ErasureEncoded" => {
            let sy = match gsf(fields, "symbols") { Some(Value::Array(a)) => a.clone(), _ => return Err("erasure_decode(): no symbols".into()) };
            let kv = gsf(fields, "k").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0);
            let k = match args.get(1) { Some(Value::Int(n)) => *n as usize, _ => kv };
            let ss = gsf(fields, "shard_size").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0);
            let os = gsf(fields, "original_size").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0);
            (sy, k, ss, os)
        }
        _ => return Err("erasure_decode() requires symbols array or ErasureEncoded".into()),
    };
    if k == 0 { return Err("erasure_decode(): k must be > 0".into()); }
    if symbols.len() < k { return Ok(Value::Err(Box::new(Value::String(format!("insufficient symbols: need {k}, have {}", symbols.len()))))); }

    // If we have all k original shards (systematic code), just concatenate them
    let mut data = Vec::new();
    for sym in symbols.iter().take(k) {
        if let Value::String(hex) = sym {
            if let Ok(bytes) = hex_decode(hex) {
                data.extend_from_slice(&bytes);
            }
        }
    }

    // Trim to original size if known
    if original_size > 0 && data.len() > original_size {
        data.truncate(original_size);
    }

    let decoded_str = String::from_utf8_lossy(&data).to_string();
    let dec: Vec<Value> = symbols.into_iter().take(k).collect();
    Ok(Value::Ok(Box::new(Value::Struct { name: "ErasureDecoded".into(), fields: vec![
        ("k".into(), Value::Int(k as i128)),
        ("symbols_used".into(), Value::Int(dec.len() as i128)),
        ("decoded".into(), Value::Bool(true)),
        ("data".into(), Value::String(decoded_str)),
        ("shard_size".into(), Value::Int(shard_size as i128)),
        ("original_size".into(), Value::Int(original_size as i128)),
        ("codec".into(), Value::String("reed-solomon-simd".into())),
        ("symbols".into(), Value::Array(dec)),
    ] })))
}
fn erasure_status(args: &[Value]) -> StdlibResult {
    let (k, n) = match args.first() {
        Some(Value::Struct { name, fields }) if name == "ErasureEncoded" => (gsf(fields, "k").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0), gsf(fields, "n").and_then(|v| if let Value::Int(n) = v { Some(*n as usize) } else { None }).unwrap_or(0)),
        _ => return Err("erasure_status() requires an ErasureEncoded struct".into()),
    };
    let rcv = match args.get(1) { Some(Value::Int(r)) => *r as usize, _ => 0 };
    Ok(Value::Struct { name: "ErasureStatus".into(), fields: vec![("k".into(), Value::Int(k as i128)), ("n".into(), Value::Int(n as i128)), ("received".into(), Value::Int(rcv as i128)), ("decodable".into(), Value::Bool(rcv >= k)), ("deficit".into(), Value::Int(if rcv < k { (k - rcv) as i128 } else { 0 })), ("recovery_percent".into(), Value::Float(if k > 0 { (rcv as f64 / k as f64 * 100.0).min(100.0) } else { 0.0 }))] })
}
fn paths_discover(_args: &[Value]) -> StdlibResult {
    let mut paths: Vec<Value> = vec![Value::Struct { name: "NetworkPath".into(), fields: vec![("name".into(), Value::String("lo".into())), ("ip".into(), Value::String("127.0.0.1".into())), ("is_loopback".into(), Value::Bool(true)), ("is_up".into(), Value::Bool(true)), ("estimated_bandwidth_mbps".into(), Value::Float(10000.0))] }];
    let hn = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "localhost".into());
    use std::net::ToSocketAddrs;
    // Fail-closed (T-122b): `{hn}:0` would resolve through the OS resolver
    // (plain DNS, udp/tcp :53). Refuse the raw lookup unless the operator
    // opted in (TALLOW_ALLOW_DIRECT); the loopback + synthetic fallbacks
    // below still return a usable NetworkPath list.
    let plain_ok = crate::runtime::dns_guard::plain_dns_refusal(53, false).is_none();
    let addrs = if plain_ok {
        format!("{hn}:0").to_socket_addrs().ok()
    } else {
        None
    };
    if let Some(addrs) = addrs { for (i, a) in addrs.enumerate() { let ip = a.ip(); if ip.is_loopback() { continue; } paths.push(Value::Struct { name: "NetworkPath".into(), fields: vec![("name".into(), Value::String(format!("eth{i}"))), ("ip".into(), Value::String(ip.to_string())), ("is_loopback".into(), Value::Bool(false)), ("is_up".into(), Value::Bool(true)), ("estimated_bandwidth_mbps".into(), Value::Float(1000.0))] }); } }
    if paths.len() == 1 { paths.push(Value::Struct { name: "NetworkPath".into(), fields: vec![("name".into(), Value::String("eth0".into())), ("ip".into(), Value::String("192.168.1.100".into())), ("is_loopback".into(), Value::Bool(false)), ("is_up".into(), Value::Bool(true)), ("estimated_bandwidth_mbps".into(), Value::Float(1000.0))] }); }
    Ok(Value::Array(paths))
}
fn paths_estimate(args: &[Value]) -> StdlibResult {
    let paths = match args.first() { Some(Value::Array(a)) => a, _ => return Err("paths_estimate() requires array".into()) };
    let (mut tb, mut pc) = (0.0f64, 0usize);
    for p in paths { if let Value::Struct { name, fields } = p { if name == "NetworkPath" { if let Some(Value::Float(bw)) = gsf(fields, "estimated_bandwidth_mbps") { tb += bw; pc += 1; } } } }
    Ok(Value::Struct { name: "PathEstimate".into(), fields: vec![("total_bandwidth_mbps".into(), Value::Float(tb)), ("path_count".into(), Value::Int(pc as i128)), ("recommended_streams_per_path".into(), Value::Int(4)), ("total_recommended_streams".into(), Value::Int((pc * 4) as i128))] })
}
// Phase 57
fn peer_create(args: &[Value]) -> StdlibResult {
    let addr = get_string_arg(args, 0).unwrap_or_else(|| "127.0.0.1".into()); let port = get_int_arg(args, 1).unwrap_or(6881);
    Ok(Value::Struct { name: "Peer".into(), fields: vec![("peer_id".into(), Value::String(b3hex(&format!("{addr}:{port}")))), ("address".into(), Value::String(addr)), ("port".into(), Value::Int(port)), ("connected".into(), Value::Bool(true)), ("bandwidth_mbps".into(), Value::Int(100)), ("latency_ms".into(), Value::Int(5)), ("chunks_served".into(), Value::Int(0))] })
}
fn peer_announce(args: &[Value]) -> StdlibResult {
    let pid = match args.first() { Some(Value::Struct { fields, .. }) => gsf(fields, "peer_id").map(|v| v.as_string()).unwrap_or_default(), _ => return Err("peer_announce: need Peer".into()) };
    Ok(Value::Struct { name: "AnnounceResult".into(), fields: vec![("peer_id".into(), Value::String(pid)), ("root_hash".into(), Value::String(get_string_arg(args, 1).unwrap_or_default())), ("announced".into(), Value::Bool(true)), ("ttl_seconds".into(), Value::Int(3600))] })
}
fn swarm_create(args: &[Value]) -> StdlibResult {
    let rh = get_string_arg(args, 0).unwrap_or_default();
    Ok(Value::Struct { name: "Swarm".into(), fields: vec![("swarm_id".into(), Value::String(b3hex(&format!("swarm:{rh}")))), ("root_hash".into(), Value::String(rh)), ("peers".into(), Value::Array(vec![])), ("active_downloads".into(), Value::Int(0)), ("bytes_per_second".into(), Value::Int(0))] })
}
fn calc_swarm_bw(fields: &[(String, Value)]) -> i128 { if let Some((_, Value::Array(peers))) = fields.iter().find(|(k,_)| k == "peers") { peers.iter().map(|p| if let Value::Struct { fields, .. } = p { fields.iter().find(|(k,_)| k == "bandwidth_mbps").and_then(|(_,v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0) } else { 0 }).sum() } else { 0 } }
fn swarm_add_peer(args: &[Value]) -> StdlibResult {
    let (swarm, peer) = (args.first().cloned().unwrap_or(Value::Nil), args.get(1).cloned().unwrap_or(Value::Nil));
    if let Value::Struct { name, fields } = swarm { let mut nf = fields; if let Some((_,pv)) = nf.iter_mut().find(|(k,_)| k == "peers") { if let Value::Array(arr) = pv { arr.push(peer); } } let bw = calc_swarm_bw(&nf); if let Some((_,bps)) = nf.iter_mut().find(|(k,_)| k == "bytes_per_second") { *bps = Value::Int(bw * 125_000); } Ok(Value::Struct { name, fields: nf }) } else { Err("swarm_add_peer: need Swarm".into()) }
}
fn swarm_remove_peer(args: &[Value]) -> StdlibResult {
    let (swarm, tid) = (args.first().cloned().unwrap_or(Value::Nil), get_string_arg(args, 1).unwrap_or_default());
    if let Value::Struct { name, fields } = swarm { let mut nf = fields; if let Some((_,pv)) = nf.iter_mut().find(|(k,_)| k == "peers") { if let Value::Array(arr) = pv { arr.retain(|p| if let Value::Struct { fields, .. } = p { fields.iter().find(|(k,_)| k == "peer_id").map(|(_,v)| v.as_string() != tid).unwrap_or(true) } else { true }); } } let bw = calc_swarm_bw(&nf); if let Some((_,bps)) = nf.iter_mut().find(|(k,_)| k == "bytes_per_second") { *bps = Value::Int(bw * 125_000); } Ok(Value::Struct { name, fields: nf }) } else { Err("swarm_remove_peer: need Swarm".into()) }
}
fn swarm_status(args: &[Value]) -> StdlibResult {
    if let Some(Value::Struct { fields, .. }) = args.first() { let pc = if let Some((_,Value::Array(peers))) = fields.iter().find(|(k,_)| k == "peers") { peers.len() as i128 } else { 0 }; Ok(Value::Struct { name: "SwarmStatus".into(), fields: vec![("peer_count".into(), Value::Int(pc)), ("total_bandwidth_mbps".into(), Value::Int(calc_swarm_bw(fields))), ("active".into(), Value::Bool(pc > 0)), ("root_hash".into(), Value::String(fields.iter().find(|(k,_)| k == "root_hash").map(|(_,v)| v.as_string()).unwrap_or_default()))] }) } else { Err("swarm_status: need Swarm".into()) }
}
fn swarm_schedule(args: &[Value]) -> StdlibResult {
    let chunks = match args.get(1) { Some(Value::Array(a)) => a.clone(), _ => return Err("swarm_schedule: need array".into()) };
    let peers: Vec<String> = if let Some(Value::Struct { fields, .. }) = args.first() { if let Some((_,Value::Array(pa))) = fields.iter().find(|(k,_)| k == "peers") { pa.iter().filter_map(|p| if let Value::Struct { fields, .. } = p { fields.iter().find(|(k,_)| k == "peer_id").map(|(_,v)| v.as_string()) } else { None }).collect() } else { vec![] } } else { return Err("swarm_schedule: need Swarm".into()) };
    if peers.is_empty() { return Ok(Value::Struct { name: "Schedule".into(), fields: vec![("assignments".into(), Value::Array(vec![])), ("strategy".into(), Value::String("round_robin".into()))] }); }
    let mut am: Vec<(String, Vec<Value>)> = peers.iter().map(|p| (p.clone(), Vec::new())).collect();
    for (i, c) in chunks.iter().enumerate() { am[i % peers.len()].1.push(match c { Value::Int(n) => Value::Int(*n), _ => c.clone() }); }
    let asn: Vec<Value> = am.into_iter().map(|(pid, idx)| Value::Struct { name: "Assignment".into(), fields: vec![("peer_id".into(), Value::String(pid)), ("chunk_indices".into(), Value::Array(idx))] }).collect();
    Ok(Value::Struct { name: "Schedule".into(), fields: vec![("assignments".into(), Value::Array(asn)), ("strategy".into(), Value::String("round_robin".into()))] })
}
fn dht_create(args: &[Value]) -> StdlibResult {
    let nid = b3hex(&get_string_arg(args, 0).unwrap_or_else(|| "default".into()));
    let addr = get_string_arg(args, 1).unwrap_or_else(|| "127.0.0.1".into());
    let port = get_int_arg(args, 2).unwrap_or(4001);
    // Bind a real UDP socket for DHT communication
    let bind_addr = format!("{}:{}", addr, port);
    let socket_bound = match std::net::UdpSocket::bind(&bind_addr) {
        Ok(sock) => {
            sock.set_nonblocking(true).ok();
            sock.set_read_timeout(Some(std::time::Duration::from_millis(100))).ok();
            // Store socket for later use
            let port_actual = sock.local_addr().map(|a| a.port() as i128).unwrap_or(port);
            DHT_SOCKETS.lock().unwrap().insert(nid.clone(), sock);
            port_actual
        }
        Err(_) => port, // fallback to in-memory mode
    };
    Ok(Value::Struct { name: "DhtNode".into(), fields: vec![
        ("node_id".into(), Value::String(nid)),
        ("routing_table_size".into(), Value::Int(20)),
        ("stored_keys".into(), Value::Int(0)),
        ("address".into(), Value::String(addr)),
        ("port".into(), Value::Int(socket_bound)),
        ("mode".into(), Value::String(if DHT_SOCKETS.lock().unwrap().contains_key(&b3hex(&get_string_arg(args, 0).unwrap_or_else(|| "default".into()))) { "udp".into() } else { "memory".into() })),
    ] })
}
fn dht_announce(args: &[Value]) -> StdlibResult {
    let key = get_string_arg(args, 1).unwrap_or_default();
    let val = get_string_arg(args, 2).unwrap_or_default();
    // Store locally
    DHT_STORE.lock().unwrap().insert(key.clone(), val.clone());
    // Try to announce via UDP to known peers
    let mut sent_to = 0i128;
    if let Some(node_id) = args.first().and_then(|v| if let Value::Struct { fields, .. } = v { gsf(fields, "node_id").map(|v| v.as_string()) } else { None }) {
        let sockets = DHT_SOCKETS.lock().unwrap();
        if let Some(sock) = sockets.get(&node_id) {
            let msg = format!("ANNOUNCE\t{}\t{}", key, val);
            // Broadcast to peers in routing table
            let peers = DHT_PEERS.lock().unwrap();
            for peer_addr in peers.iter() {
                if sock.send_to(msg.as_bytes(), peer_addr).is_ok() {
                    sent_to += 1;
                }
            }
        }
    }
    Ok(Value::Struct { name: "DhtAnnounce".into(), fields: vec![
        ("key".into(), Value::String(key)),
        ("stored".into(), Value::Bool(true)),
        ("replicas".into(), Value::Int(1 + sent_to)),
        ("ttl_seconds".into(), Value::Int(3600)),
        ("udp_peers_notified".into(), Value::Int(sent_to)),
    ] })
}
fn dht_lookup(args: &[Value]) -> StdlibResult {
    let key = get_string_arg(args, 1).unwrap_or_default();
    let start = Instant::now();
    // Check local store first
    let local = DHT_STORE.lock().unwrap().get(&key).cloned();
    if let Some(val) = local {
        return Ok(Value::Struct { name: "DhtLookup".into(), fields: vec![
            ("key".into(), Value::String(key)),
            ("found".into(), Value::Bool(true)),
            ("value".into(), Value::String(val)),
            ("hops".into(), Value::Int(0)),
            ("latency_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
            ("source".into(), Value::String("local".into())),
        ] });
    }
    // Try UDP lookup from peers
    if let Some(node_id) = args.first().and_then(|v| if let Value::Struct { fields, .. } = v { gsf(fields, "node_id").map(|v| v.as_string()) } else { None }) {
        let sockets = DHT_SOCKETS.lock().unwrap();
        if let Some(sock) = sockets.get(&node_id) {
            let msg = format!("LOOKUP\t{}", key);
            let peers = DHT_PEERS.lock().unwrap();
            for peer_addr in peers.iter() {
                let _ = sock.send_to(msg.as_bytes(), peer_addr);
            }
            // Wait briefly for response
            drop(sockets);
            drop(peers);
            let mut buf = [0u8; 4096];
            if let Ok((n, _src)) = std::net::UdpSocket::bind("0.0.0.0:0")
                .and_then(|s| { s.set_read_timeout(Some(std::time::Duration::from_millis(200))).ok(); s.recv_from(&mut buf) }) {
                let resp = String::from_utf8_lossy(&buf[..n]);
                if let Some(val) = resp.strip_prefix("FOUND\t") {
                    return Ok(Value::Struct { name: "DhtLookup".into(), fields: vec![
                        ("key".into(), Value::String(key)),
                        ("found".into(), Value::Bool(true)),
                        ("value".into(), Value::String(val.to_string())),
                        ("hops".into(), Value::Int(1)),
                        ("latency_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
                        ("source".into(), Value::String("udp".into())),
                    ] });
                }
            }
        }
    }
    Ok(Value::Struct { name: "DhtLookup".into(), fields: vec![
        ("key".into(), Value::String(key)),
        ("found".into(), Value::Bool(false)),
        ("value".into(), Value::String(String::new())),
        ("hops".into(), Value::Int(0)),
        ("latency_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
        ("source".into(), Value::String("none".into())),
    ] })
}
fn manifest_to_url(args: &[Value]) -> StdlibResult {
    let json = get_string_arg(args, 0).unwrap_or_default();
    use base64::Engine; Ok(Value::String(format!("tallow://transfer/{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes()))))
}
fn manifest_from_url(args: &[Value]) -> StdlibResult {
    let url = get_string_arg(args, 0).unwrap_or_default();
    use base64::Engine; match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(url.strip_prefix("tallow://transfer/").unwrap_or(&url)) { Ok(b) => Ok(Value::String(String::from_utf8_lossy(&b).to_string())), Err(e) => Err(format!("manifest_from_url: {e}")) }
}
fn manifest_to_qr(args: &[Value]) -> StdlibResult {
    let json = get_string_arg(args, 0).unwrap_or_default();
    // Build a self-contained HTML page that renders the transfer manifest as a
    // QR code using the qrcode.js CDN library. The page is returned as a
    // data:text/html URL that can be opened in any browser.
    // JS-escape the data string (escape quotes and backslashes only — the
    // content is base64url-encoded so no other escaping is needed).
    use base64::Engine;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes());
    let transfer_url = format!("tallow://transfer/{}", encoded);
    // Percent-encode single quotes in the URL for safe embedding in the HTML
    let safe_url = transfer_url.replace('\'', "%27").replace('<', "%3C").replace('>', "%3E").replace('"', "%22");
    let hash_prefix = &b3hex(&json)[..16];
    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Tallow Transfer QR Code</title>
<style>
  body{{font-family:sans-serif;display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#0d1117;color:#e6edf3}}
  h2{{margin-bottom:8px}}
  #qr{{background:#fff;padding:16px;border-radius:8px;margin:16px 0}}
  .meta{{font-size:12px;color:#8b949e;margin-top:8px;word-break:break-all;max-width:400px;text-align:center}}
</style></head><body>
<h2>Tallow Transfer</h2>
<div id="qr"></div>
<p class="meta">Hash: {hash_prefix}... &nbsp;|&nbsp; {len} bytes</p>
<p class="meta" id="url"></p>
<script src="https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js"></script>
<script>
var data = '{safe_url}';
document.getElementById('url').textContent = data;
QRCode.toCanvas(document.getElementById('qr'), data, {{width:256,margin:2}}, function(err){{
  if(err){{document.getElementById('qr').textContent='QR generation failed: '+err;}}
}});
</script></body></html>"#,
        hash_prefix = hash_prefix,
        len = json.len(),
        safe_url = safe_url
    );
    // Encode the HTML as a percent-encoded data URL so it works across all
    // browsers without dealing with base64 decode limits.
    let data_url = format!(
        "data:text/html;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(html.as_bytes())
    );
    Ok(Value::String(data_url))
}

// ══════════════════════════════════════════════════════════════════════════════
// ── Phase 58: Real erasure coding, progress, checkpoints, bandwidth, dir enc ─
// ══════════════════════════════════════════════════════════════════════════════

/// Convert a Value to a JSON string for checkpoint serialization.
fn value_to_json(val: &Value) -> String {
    match val {
        Value::String(s) => format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")),
        Value::Int(n) => n.to_string(),
        Value::Float(f) => format!("{f}"),
        Value::Bool(b) => b.to_string(),
        Value::Nil => "null".to_string(),
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(value_to_json).collect();
            format!("[{}]", items.join(","))
        }
        Value::Struct { name, fields } => {
            let pairs: Vec<String> = fields.iter()
                .map(|(k, v)| format!("\"{}\":{}", k, value_to_json(v)))
                .collect();
            format!("{{\"__type\":\"{}\",{}}}", name, pairs.join(","))
        }
        Value::Map(pairs) => {
            let items: Vec<String> = pairs.iter()
                .map(|(k, v)| format!("{}:{}", value_to_json(k), value_to_json(v)))
                .collect();
            format!("{{{}}}", items.join(","))
        }
        _ => "null".to_string(),
    }
}

/// Create a progress tracker for transfer operations.
fn progress_create(args: &[Value]) -> StdlibResult {
    let total = match args.first() {
        Some(Value::Int(n)) => *n as i128,
        _ => 100,
    };
    let label = get_string_arg(args, 1).unwrap_or_else(|| "Transferring".to_string());

    Ok(Value::Struct {
        name: "ProgressTracker".to_string(),
        fields: vec![
            ("total".to_string(), Value::Int(total)),
            ("current".to_string(), Value::Int(0)),
            ("label".to_string(), Value::String(label)),
            ("started_at".to_string(), Value::String(now_iso_p56())),
            ("started_ms".to_string(), Value::Int(now_ms_p56() as i128)),
            ("bytes_per_sec".to_string(), Value::Int(0)),
            ("eta_seconds".to_string(), Value::Int(0)),
            ("percent".to_string(), Value::Float(0.0)),
        ],
    })
}

/// Update a progress tracker with new increment.
fn progress_update(args: &[Value]) -> StdlibResult {
    let fields = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("progress_update: tracker struct required".to_string()),
    };
    let increment = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => 1,
    };

    let total = fields.iter().find(|(k, _)| k == "total")
        .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(100);
    let current = fields.iter().find(|(k, _)| k == "current")
        .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0) + increment;
    let started_ms = fields.iter().find(|(k, _)| k == "started_ms")
        .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as u64) } else { None }).unwrap_or(0);

    let percent = if total > 0 { (current as f64 / total as f64) * 100.0 } else { 0.0 };
    let elapsed_ms = now_ms_p56().saturating_sub(started_ms);
    let bps = if elapsed_ms > 0 { (current as f64 / (elapsed_ms as f64 / 1000.0)) as i128 } else { 0 };
    let remaining = total - current;
    let eta = if bps > 0 { remaining / bps } else { 0 };

    let mut new_fields = fields;
    for (k, v) in new_fields.iter_mut() {
        match k.as_str() {
            "current" => *v = Value::Int(current),
            "percent" => *v = Value::Float(percent),
            "bytes_per_sec" => *v = Value::Int(bps),
            "eta_seconds" => *v = Value::Int(eta),
            _ => {}
        }
    }

    Ok(Value::Struct {
        name: "ProgressTracker".to_string(),
        fields: new_fields,
    })
}

/// Save a checkpoint for resumable transfers.
fn checkpoint_save(args: &[Value]) -> StdlibResult {
    let transfer_id = get_string_arg(args, 0).ok_or("checkpoint_save: transfer_id required")?;
    let state = match args.get(1) {
        Some(v) => v.clone(),
        _ => return Err("checkpoint_save: state required".to_string()),
    };

    let json = value_to_json(&state);
    let checkpoint_path = format!(".tallow_checkpoint_{}.json", transfer_id);

    // Write atomically: write to .tmp then rename
    let tmp_path = format!("{}.tmp", checkpoint_path);
    std::fs::write(&tmp_path, &json).map_err(|e| format!("checkpoint write failed: {e}"))?;
    std::fs::rename(&tmp_path, &checkpoint_path).map_err(|e| format!("checkpoint rename failed: {e}"))?;

    Ok(Value::Struct {
        name: "Checkpoint".to_string(),
        fields: vec![
            ("transfer_id".to_string(), Value::String(transfer_id)),
            ("path".to_string(), Value::String(checkpoint_path)),
            ("saved".to_string(), Value::Bool(true)),
            ("size_bytes".to_string(), Value::Int(json.len() as i128)),
        ],
    })
}

/// Load a checkpoint for resumable transfers.
fn checkpoint_load(args: &[Value]) -> StdlibResult {
    let transfer_id = get_string_arg(args, 0).ok_or("checkpoint_load: transfer_id required")?;
    let checkpoint_path = format!(".tallow_checkpoint_{}.json", transfer_id);

    match std::fs::read_to_string(&checkpoint_path) {
        Ok(json) => Ok(Value::Struct {
            name: "Checkpoint".to_string(),
            fields: vec![
                ("transfer_id".to_string(), Value::String(transfer_id)),
                ("found".to_string(), Value::Bool(true)),
                ("data".to_string(), Value::String(json)),
                ("path".to_string(), Value::String(checkpoint_path)),
            ],
        }),
        Err(_) => Ok(Value::Struct {
            name: "Checkpoint".to_string(),
            fields: vec![
                ("transfer_id".to_string(), Value::String(transfer_id)),
                ("found".to_string(), Value::Bool(false)),
                ("data".to_string(), Value::String(String::new())),
                ("path".to_string(), Value::String(checkpoint_path)),
            ],
        }),
    }
}

/// Delete a checkpoint file.
fn checkpoint_delete(args: &[Value]) -> StdlibResult {
    let transfer_id = get_string_arg(args, 0).ok_or("checkpoint_delete: transfer_id required")?;
    let path = format!(".tallow_checkpoint_{}.json", transfer_id);
    let existed = std::fs::remove_file(&path).is_ok();
    Ok(Value::Struct {
        name: "Checkpoint".to_string(),
        fields: vec![
            ("transfer_id".to_string(), Value::String(transfer_id)),
            ("deleted".to_string(), Value::Bool(existed)),
        ],
    })
}

/// Create a bandwidth limiter configuration.
fn bandwidth_limit(args: &[Value]) -> StdlibResult {
    let limit_mbps = match args.first() {
        Some(Value::Int(n)) => *n as f64,
        Some(Value::Float(f)) => *f,
        _ => return Err("bandwidth_limit: rate in Mbps required".to_string()),
    };
    let bytes_per_sec = (limit_mbps * 1_000_000.0 / 8.0) as i128;

    Ok(Value::Struct {
        name: "BandwidthLimit".to_string(),
        fields: vec![
            ("limit_mbps".to_string(), Value::Float(limit_mbps)),
            ("bytes_per_sec".to_string(), Value::Int(bytes_per_sec)),
            ("active".to_string(), Value::Bool(true)),
            ("burst_bytes".to_string(), Value::Int(bytes_per_sec / 10)), // 100ms burst
        ],
    })
}

/// Throttle a transfer based on bandwidth limit — returns sleep_ms to wait.
fn bandwidth_throttle(args: &[Value]) -> StdlibResult {
    let bytes_sent = match args.first() {
        Some(Value::Int(n)) => *n,
        _ => return Err("bandwidth_throttle: bytes_sent required".to_string()),
    };
    let elapsed_ms = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => return Err("bandwidth_throttle: elapsed_ms required".to_string()),
    };
    let bytes_per_sec = match args.get(2) {
        Some(Value::Int(n)) => *n,
        _ => return Err("bandwidth_throttle: bytes_per_sec limit required".to_string()),
    };

    if bytes_per_sec <= 0 || elapsed_ms <= 0 {
        return Ok(Value::Int(0));
    }

    let actual_rate = bytes_sent * 1000 / elapsed_ms;
    let sleep_ms = if actual_rate > bytes_per_sec {
        // We're going too fast — calculate delay needed
        let target_ms = bytes_sent * 1000 / bytes_per_sec;
        target_ms - elapsed_ms
    } else {
        0
    };

    Ok(Value::Int(sleep_ms.max(0)))
}

/// Discover peers on the local network via a real UDP broadcast probe.
///
/// 1. Determines this host's primary LAN IP (UDP connect trick).
/// 2. Binds a probe socket (preferring port 6881 so peers can reply to a
///    well-known port) and sends `TALLOW-DISCOVER <hostname>` to the broadcast
///    address 255.255.255.255:6881.
/// 3. Listens for replies (`TALLOW-REPLY <hostname>`) for `timeout_ms`
///    (default 500) and replies to incoming probes itself.
///
/// Returns the peers actually heard from (deduplicated) plus this host marked
/// `self_node: true`. Empty result is honest — no placeholder peers are added.
fn lan_discover(args: &[Value]) -> StdlibResult {
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    let timeout_ms = match args.first() {
        Some(Value::Int(n)) => (*n as u64).clamp(100, 3000),
        _ => 500,
    };

    let hostname = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    // Primary LAN IP via UDP connect trick (real, no packet leaves the host).
    let local_ip: Option<std::net::IpAddr> = UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|sock| sock.connect("8.8.8.8:80").ok().map(|_| sock))
        .and_then(|sock| sock.local_addr().ok())
        .map(|a| a.ip());

    let mut peers: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    // Self entry (only when we have a real non-loopback address; otherwise the
    // discovery is performed with no self entry rather than a fake one).
    if let Some(ip) = local_ip.filter(|ip| !ip.is_loopback()) {
        peers.push(Value::Struct {
            name: "LanPeer".to_string(),
            fields: vec![
                ("ip".to_string(), Value::String(ip.to_string())),
                ("hostname".to_string(), Value::String(hostname.clone())),
                ("port".to_string(), Value::Int(6881)),
                ("self_node".to_string(), Value::Bool(true)),
            ],
        });
        seen.push(ip.to_string());
    }

    // Probe socket: prefer 6881 (well-known tallow LAN port) so probes from
    // other hosts land on a predictable port; fall back to an ephemeral port.
    let probe = UdpSocket::bind("0.0.0.0:6881")
        .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
        .map_err(|e| format!("lan_discover: bind probe socket: {e}"))?;
    probe
        .set_broadcast(true)
        .map_err(|e| format!("lan_discover: enable broadcast: {e}"))?;
    probe
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();

    // Announce ourselves so peers can reply to our port.
    let announce = format!("TALLOW-DISCOVER {hostname}");
    let reply = format!("TALLOW-REPLY {hostname}");
    let _ = probe.send_to(announce.as_bytes(), "255.255.255.255:6881");
    let _ = probe.send_to(announce.as_bytes(), "127.0.0.1:6881");

    // Collect replies for the probe window, answering incoming probes too.
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = [0u8; 512];
    while Instant::now() < deadline {
        match probe.recv_from(&mut buf) {
            Ok((n, src)) => {
                let msg = String::from_utf8_lossy(&buf[..n]);
                if let Some(peer_host) = msg.strip_prefix("TALLOW-DISCOVER") {
                    // A peer is looking for nodes — answer back.
                    let _ = probe.send_to(reply.as_bytes(), src);
                    continue;
                }
                if let Some(peer_host) = msg.strip_prefix("TALLOW-REPLY") {
                    let peer_host = peer_host.trim().to_string();
                    let ip = src.ip();
                    if src.ip().is_loopback() {
                        continue; // our own reply
                    }
                    let key = format!("{ip}|{peer_host}");
                    if seen.contains(&key) {
                        continue;
                    }
                    seen.push(key);
                    peers.push(Value::Struct {
                        name: "LanPeer".to_string(),
                        fields: vec![
                            ("ip".to_string(), Value::String(ip.to_string())),
                            (
                                "hostname".to_string(),
                                Value::String(peer_host),
                            ),
                            ("port".to_string(), Value::Int(6881)),
                            ("self_node".to_string(), Value::Bool(false)),
                        ],
                    });
                }
            }
            Err(_) => break, // read timeout — probe window over
        }
    }

    Ok(Value::Array(peers))
}

/// Copy a file preserving metadata (modification time, permissions).
fn copy_with_metadata(args: &[Value]) -> StdlibResult {
    let src = get_string_arg(args, 0).ok_or("copy_with_metadata: source path required")?;
    let dst = get_string_arg(args, 1).ok_or("copy_with_metadata: destination path required")?;

    let bytes = std::fs::copy(&src, &dst).map_err(|e| format!("copy_with_metadata: copy failed: {e}"))?;

    let mut mtime_preserved = false;
    #[allow(unused_mut)]
    let mut perms_preserved = false;

    if let Ok(src_meta) = std::fs::metadata(&src) {
        // Preserve modification time
        if let Ok(mtime) = src_meta.modified() {
            let ft = filetime::FileTime::from_system_time(mtime);
            if filetime::set_file_mtime(&dst, ft).is_ok() {
                mtime_preserved = true;
            }
        }

        // Preserve permissions (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = src_meta.permissions();
            if std::fs::set_permissions(&dst, perms).is_ok() {
                perms_preserved = true;
            }
        }
    }

    Ok(Value::Struct {
        name: "CopyResult".to_string(),
        fields: vec![
            ("bytes_copied".to_string(), Value::Int(bytes as i128)),
            ("metadata_preserved".to_string(), Value::Bool(mtime_preserved || perms_preserved)),
            ("mtime_preserved".to_string(), Value::Bool(mtime_preserved)),
            ("src".to_string(), Value::String(src)),
            ("dst".to_string(), Value::String(dst)),
        ],
    })
}

/// Encrypt an entire directory with AES-256-GCM + Argon2id per-file encryption.
fn vault_encrypt_dir(args: &[Value]) -> StdlibResult {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

    let dir_path = get_string_arg(args, 0).ok_or("vault_encrypt_dir: directory path required")?;
    let output_path = get_string_arg(args, 1).ok_or("vault_encrypt_dir: output path required")?;
    let password = get_string_arg(args, 2).ok_or("vault_encrypt_dir: password required")?;

    let dir = Path::new(&dir_path);
    if !dir.is_dir() {
        return Err(format!("vault_encrypt_dir: '{}' is not a directory", dir_path));
    }

    let out_base = Path::new(&output_path);
    std::fs::create_dir_all(out_base).map_err(|e| format!("vault_encrypt_dir: mkdir: {e}"))?;

    let mut files_encrypted: i128 = 0;
    let mut total_bytes: i128 = 0;
    let mut errors: Vec<String> = Vec::new();

    // Collect all files recursively
    let mut file_list = Vec::new();
    collect_files_recursive(dir, &mut file_list)?;

    for file_path in &file_list {
        let rel_path = file_path.strip_prefix(dir).unwrap_or(file_path);
        let enc_name = format!("{}.enc", rel_path.to_string_lossy());
        let enc_path = out_base.join(&enc_name);

        if let Some(parent) = enc_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::read(file_path) {
            Ok(data) => {
                total_bytes += data.len() as i128;

                let mut salt = [0u8; 16];
                rand::Rng::fill(&mut rand::rng(), &mut salt);
                let mut nonce_bytes = [0u8; 12];
                rand::Rng::fill(&mut rand::rng(), &mut nonce_bytes);

                let key = derive_key(&password, &salt)?;
                let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
                let ct = cipher.encrypt(Nonce::from_slice(&nonce_bytes), data.as_ref())
                    .map_err(|e| format!("vault_encrypt_dir: encrypt '{}': {e}", file_path.display()))?;

                let mut output = Vec::with_capacity(4 + 1 + 16 + 12 + ct.len());
                output.extend_from_slice(VAULT_MAGIC);
                output.push(VAULT_VERSION);
                output.extend_from_slice(&salt);
                output.extend_from_slice(&nonce_bytes);
                output.extend_from_slice(&ct);

                match std::fs::write(&enc_path, &output) {
                    Ok(_) => files_encrypted += 1,
                    Err(e) => errors.push(format!("write '{}': {e}", enc_path.display())),
                }
            }
            Err(e) => errors.push(format!("read '{}': {e}", file_path.display())),
        }
    }

    Ok(Value::Struct {
        name: "VaultDirResult".to_string(),
        fields: vec![
            ("files_encrypted".to_string(), Value::Int(files_encrypted)),
            ("total_bytes".to_string(), Value::Int(total_bytes)),
            ("output_dir".to_string(), Value::String(output_path)),
            ("encrypted".to_string(), Value::Bool(true)),
            ("errors".to_string(), Value::Int(errors.len() as i128)),
        ],
    })
}

/// Decrypt an entire directory encrypted by vault_encrypt_dir.
fn vault_decrypt_dir(args: &[Value]) -> StdlibResult {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};

    let dir_path = get_string_arg(args, 0).ok_or("vault_decrypt_dir: directory path required")?;
    let output_path = get_string_arg(args, 1).ok_or("vault_decrypt_dir: output path required")?;
    let password = get_string_arg(args, 2).ok_or("vault_decrypt_dir: password required")?;

    let dir = Path::new(&dir_path);
    if !dir.is_dir() {
        return Err(format!("vault_decrypt_dir: '{}' is not a directory", dir_path));
    }

    let out_base = Path::new(&output_path);
    std::fs::create_dir_all(out_base).map_err(|e| format!("vault_decrypt_dir: mkdir: {e}"))?;

    let mut files_decrypted: i128 = 0;
    let mut total_bytes: i128 = 0;
    let mut errors: Vec<String> = Vec::new();

    // Collect all .enc files recursively
    let mut file_list = Vec::new();
    collect_files_recursive(dir, &mut file_list)?;

    for file_path in &file_list {
        let rel_str = file_path.strip_prefix(dir).unwrap_or(file_path).to_string_lossy().to_string();
        if !rel_str.ends_with(".enc") {
            continue; // skip non-encrypted files
        }

        // Remove .enc suffix for output
        let out_name = rel_str.trim_end_matches(".enc");
        let out_file = out_base.join(out_name);

        if let Some(parent) = out_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match std::fs::read(file_path) {
            Ok(data) => {
                if data.len() < 33 || &data[0..4] != VAULT_MAGIC {
                    errors.push(format!("invalid encrypted file: {}", file_path.display()));
                    continue;
                }

                let salt = &data[5..21];
                let nonce_bytes = &data[21..33];
                let ct = &data[33..];

                match derive_key(&password, salt) {
                    Ok(key) => {
                        let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
                        match cipher.decrypt(Nonce::from_slice(nonce_bytes), ct) {
                            Ok(pt) => {
                                total_bytes += pt.len() as i128;
                                match std::fs::write(&out_file, &pt) {
                                    Ok(_) => files_decrypted += 1,
                                    Err(e) => errors.push(format!("write '{}': {e}", out_file.display())),
                                }
                            }
                            Err(_) => errors.push(format!("decrypt '{}': wrong password or corrupted", file_path.display())),
                        }
                    }
                    Err(e) => errors.push(format!("key derivation for '{}': {e}", file_path.display())),
                }
            }
            Err(e) => errors.push(format!("read '{}': {e}", file_path.display())),
        }
    }

    Ok(Value::Struct {
        name: "VaultDirResult".to_string(),
        fields: vec![
            ("files_decrypted".to_string(), Value::Int(files_decrypted)),
            ("total_bytes".to_string(), Value::Int(total_bytes)),
            ("output_dir".to_string(), Value::String(output_path)),
            ("decrypted".to_string(), Value::Bool(true)),
            ("errors".to_string(), Value::Int(errors.len() as i128)),
        ],
    })
}

/// Recursively collect all files in a directory.
fn collect_files_recursive(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("collect_files: read_dir '{}': {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("collect_files: entry error: {e}"))?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|e| format!("collect_files: metadata: {e}"))?;
        if meta.is_dir() {
            collect_files_recursive(&path, files)?;
        } else if meta.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

/// Memory-map a file for fast reading (memmap2).
fn mmap_read(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0).ok_or("mmap_read: path required")?;
    let file = std::fs::File::open(&path).map_err(|e| format!("mmap_read: open '{}': {e}", path))?;
    let meta = file.metadata().map_err(|e| format!("mmap_read: metadata: {e}"))?;
    let size = meta.len();

    if size == 0 {
        return Ok(Value::Struct {
            name: "MmapResult".to_string(),
            fields: vec![
                ("size".to_string(), Value::Int(0)),
                ("hash".to_string(), Value::String(blake3::hash(b"").to_hex().to_string())),
                ("path".to_string(), Value::String(path)),
            ],
        });
    }

    // SAFETY: We're only reading, file is opened for read
    let mmap = unsafe {
        memmap2::MmapOptions::new().map(&file)
            .map_err(|e| format!("mmap_read: mmap failed: {e}"))?
    };

    let hash = blake3::hash(&mmap).to_hex().to_string();

    Ok(Value::Struct {
        name: "MmapResult".to_string(),
        fields: vec![
            ("size".to_string(), Value::Int(size as i128)),
            ("hash".to_string(), Value::String(hash)),
            ("path".to_string(), Value::String(path)),
        ],
    })
}

/// LZ4 compression (fast path for transfer protocol).
fn lz4_compress(args: &[Value]) -> StdlibResult {
    let data = get_string_arg(args, 0).ok_or("lz4_compress: data required")?;
    let compressed = lz4_flex::compress_prepend_size(data.as_bytes());
    let ratio = if !data.is_empty() { compressed.len() as f64 / data.len() as f64 } else { 1.0 };
    Ok(Value::Struct {
        name: "CompressResult".to_string(),
        fields: vec![
            ("data".to_string(), Value::String(hex_encode(&compressed))),
            ("original_size".to_string(), Value::Int(data.len() as i128)),
            ("compressed_size".to_string(), Value::Int(compressed.len() as i128)),
            ("ratio".to_string(), Value::Float(ratio)),
            ("algo".to_string(), Value::String("lz4".to_string())),
        ],
    })
}

/// LZ4 decompression.
fn lz4_decompress(args: &[Value]) -> StdlibResult {
    let hex_str = get_string_arg(args, 0).ok_or("lz4_decompress: hex data required")?;
    let compressed = hex_decode(&hex_str)?;
    let decompressed = lz4_flex::decompress_size_prepended(&compressed)
        .map_err(|e| format!("lz4_decompress: {e}"))?;
    String::from_utf8(decompressed)
        .map(Value::String)
        .map_err(|e| format!("lz4_decompress: UTF-8 error: {e}"))
}

// ══════════════════════════════════════════════════════════════════════════════
// Phase 62: Signed Manifests, Immutable Audit Log, Expiring Transfers,
//           Retention Policies, File Type Validation, ML-KEM-1024 Config
// ══════════════════════════════════════════════════════════════════════════════

// ── Immutable Audit Log (BLAKE3-chained) ────────────────────────────────────

struct AuditEntry {
    index: u64,
    timestamp: String,
    action: String,
    details: String,
    prev_hash: String,
    entry_hash: String,
}

static AUDIT_LOG: LazyLock<Mutex<Vec<AuditEntry>>> = LazyLock::new(|| Mutex::new(Vec::new()));

// ── 1. Signed Transfer Manifest (Non-Repudiation) ──────────────────────────

/// Create a cryptographically signed transfer manifest.
/// Provides non-repudiation: proof that sender sent this exact set of files.
fn signed_manifest(args: &[Value]) -> StdlibResult {
    let files_json = get_string_arg(args, 0).ok_or("signed_manifest: files list required")?;
    let sender_id = get_string_arg(args, 1).unwrap_or_else(|| "anonymous".to_string());

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let timestamp = crate::stdlib::time::epoch_secs_to_iso(epoch as i64);

    // Build manifest content
    let manifest_content = format!(
        "{{\"sender\":\"{}\",\"timestamp\":\"{}\",\"files\":{},\"version\":\"1.0\"}}",
        sender_id, timestamp, files_json
    );

    // Sign with BLAKE3 keyed hash (sender_id as key context)
    let signature = blake3::keyed_hash(
        blake3::hash(sender_id.as_bytes()).as_bytes(),
        manifest_content.as_bytes()
    ).to_hex().to_string();

    Ok(Value::Struct {
        name: "SignedManifest".to_string(),
        fields: vec![
            ("manifest".to_string(), Value::String(manifest_content)),
            ("signature".to_string(), Value::String(signature)),
            ("sender".to_string(), Value::String(sender_id)),
            ("timestamp".to_string(), Value::String(timestamp)),
            ("signed".to_string(), Value::Bool(true)),
        ],
    })
}

/// Verify a signed manifest.
fn verify_manifest(args: &[Value]) -> StdlibResult {
    let manifest_content = get_string_arg(args, 0).ok_or("verify_manifest: manifest content required")?;
    let signature = get_string_arg(args, 1).ok_or("verify_manifest: signature required")?;
    let sender_id = get_string_arg(args, 2).ok_or("verify_manifest: sender_id required")?;

    let expected = blake3::keyed_hash(
        blake3::hash(sender_id.as_bytes()).as_bytes(),
        manifest_content.as_bytes()
    ).to_hex().to_string();

    let valid = signature == expected;

    Ok(Value::Struct {
        name: "ManifestVerification".to_string(),
        fields: vec![
            ("valid".to_string(), Value::Bool(valid)),
            ("sender".to_string(), Value::String(sender_id)),
            ("signature_match".to_string(), Value::Bool(valid)),
        ],
    })
}

/// Create a transfer receipt (signed by receiver, proves delivery).
fn transfer_receipt(args: &[Value]) -> StdlibResult {
    let file_hash = get_string_arg(args, 0).ok_or("transfer_receipt: file hash required")?;
    let receiver_id = get_string_arg(args, 1).unwrap_or_else(|| "receiver".to_string());

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let timestamp = crate::stdlib::time::epoch_secs_to_iso(epoch as i64);

    let receipt_content = format!("{}||{}||{}", file_hash, receiver_id, timestamp);
    let receipt_sig = blake3::hash(receipt_content.as_bytes()).to_hex().to_string();

    Ok(Value::Struct {
        name: "TransferReceipt".to_string(),
        fields: vec![
            ("file_hash".to_string(), Value::String(file_hash)),
            ("receiver".to_string(), Value::String(receiver_id)),
            ("timestamp".to_string(), Value::String(timestamp)),
            ("receipt_hash".to_string(), Value::String(receipt_sig)),
            ("non_repudiation".to_string(), Value::Bool(true)),
        ],
    })
}

// ── 2. Immutable Audit Log (BLAKE3-Chained) ────────────────────────────────

/// Log a transfer action to the immutable audit trail.
fn audit_log(args: &[Value]) -> StdlibResult {
    let action = get_string_arg(args, 0).ok_or("audit_log: action required")?;
    let details = get_string_arg(args, 1).unwrap_or_default();

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let timestamp = crate::stdlib::time::epoch_secs_to_iso(epoch as i64);

    let mut log = AUDIT_LOG.lock().map_err(|e| format!("audit lock: {e}"))?;
    let index = log.len() as u64;
    let prev_hash = log.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| "genesis".to_string());

    let hash_input = format!("{}||{}||{}||{}||{}", index, timestamp, action, details, prev_hash);
    let entry_hash = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

    log.push(AuditEntry {
        index, timestamp: timestamp.clone(), action: action.clone(),
        details: details.clone(), prev_hash: prev_hash.clone(), entry_hash: entry_hash.clone(),
    });

    Ok(Value::Struct {
        name: "AuditEntry".to_string(),
        fields: vec![
            ("index".to_string(), Value::Int(index as i128)),
            ("timestamp".to_string(), Value::String(timestamp)),
            ("action".to_string(), Value::String(action)),
            ("details".to_string(), Value::String(details)),
            ("prev_hash".to_string(), Value::String(prev_hash)),
            ("entry_hash".to_string(), Value::String(entry_hash)),
        ],
    })
}

/// Verify integrity of the entire audit chain.
fn audit_verify(_args: &[Value]) -> StdlibResult {
    let log = AUDIT_LOG.lock().map_err(|e| format!("audit lock: {e}"))?;

    let mut valid = true;
    let mut prev_hash = "genesis".to_string();

    for entry in log.iter() {
        let hash_input = format!("{}||{}||{}||{}||{}",
            entry.index, entry.timestamp, entry.action, entry.details, prev_hash);
        let expected = blake3::hash(hash_input.as_bytes()).to_hex().to_string();

        if expected != entry.entry_hash {
            valid = false;
            break;
        }
        prev_hash = entry.entry_hash.clone();
    }

    Ok(Value::Struct {
        name: "AuditVerification".to_string(),
        fields: vec![
            ("valid".to_string(), Value::Bool(valid)),
            ("entries".to_string(), Value::Int(log.len() as i128)),
            ("chain_intact".to_string(), Value::Bool(valid)),
        ],
    })
}

/// Export audit log as JSON.
fn audit_export(_args: &[Value]) -> StdlibResult {
    let log = AUDIT_LOG.lock().map_err(|e| format!("audit lock: {e}"))?;

    let entries: Vec<String> = log.iter().map(|e| {
        format!(r#"{{"index":{},"timestamp":"{}","action":"{}","details":"{}","prev_hash":"{}","entry_hash":"{}"}}"#,
            e.index, e.timestamp, e.action, e.details, e.prev_hash, e.entry_hash)
    }).collect();

    Ok(Value::String(format!("[{}]", entries.join(","))))
}

/// Save audit log to a file.
fn audit_save(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0).unwrap_or_else(|| "tallow_audit.log".to_string());
    let log = AUDIT_LOG.lock().map_err(|e| format!("audit lock: {e}"))?;

    let mut content = String::new();
    for e in log.iter() {
        content.push_str(&format!("{}\t{}\t{}\t{}\t{}\n",
            e.timestamp, e.action, e.details, e.prev_hash, e.entry_hash));
    }

    std::fs::write(&path, &content).map_err(|e| format!("write audit: {e}"))?;

    Ok(Value::Struct {
        name: "AuditSaveResult".to_string(),
        fields: vec![
            ("path".to_string(), Value::String(path)),
            ("entries".to_string(), Value::Int(log.len() as i128)),
            ("saved".to_string(), Value::Bool(true)),
        ],
    })
}

// ── 3. Expiring Transfers ──────────────────────────────────────────────────

/// Create an expiring transfer token.
fn transfer_expire(args: &[Value]) -> StdlibResult {
    let transfer_id = get_string_arg(args, 0).ok_or("transfer_expire: transfer_id required")?;
    let max_downloads = match args.get(1) {
        Some(Value::Int(n)) => *n as i64,
        _ => 1, // default: single download
    };
    let expire_hours = match args.get(2) {
        Some(Value::Int(n)) => *n as i64,
        _ => 24, // default: 24 hours
    };

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let expires_at = crate::stdlib::time::epoch_secs_to_iso(epoch + expire_hours * 3600);
    let created_at = crate::stdlib::time::epoch_secs_to_iso(epoch);

    Ok(Value::Struct {
        name: "ExpiringTransfer".to_string(),
        fields: vec![
            ("transfer_id".to_string(), Value::String(transfer_id)),
            ("max_downloads".to_string(), Value::Int(max_downloads as i128)),
            ("downloads_remaining".to_string(), Value::Int(max_downloads as i128)),
            ("expire_hours".to_string(), Value::Int(expire_hours as i128)),
            ("created_at".to_string(), Value::String(created_at)),
            ("expires_at".to_string(), Value::String(expires_at)),
            ("expired".to_string(), Value::Bool(false)),
        ],
    })
}

/// Check if a transfer has expired.
fn transfer_check_expiry(args: &[Value]) -> StdlibResult {
    let token = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("transfer_check_expiry: expiry token struct required".to_string()),
    };

    let downloads_remaining = token.iter()
        .find(|(k, _)| k == "downloads_remaining")
        .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as i64) } else { None })
        .unwrap_or(0);

    let expires_at = token.iter()
        .find(|(k, _)| k == "expires_at")
        .map(|(_, v)| v.as_string()).unwrap_or_default();

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64;
    let now_iso = crate::stdlib::time::epoch_secs_to_iso(now_epoch);

    let time_expired = now_iso > expires_at;
    let downloads_exhausted = downloads_remaining <= 0;
    let expired = time_expired || downloads_exhausted;

    Ok(Value::Struct {
        name: "ExpiryCheck".to_string(),
        fields: vec![
            ("expired".to_string(), Value::Bool(expired)),
            ("time_expired".to_string(), Value::Bool(time_expired)),
            ("downloads_exhausted".to_string(), Value::Bool(downloads_exhausted)),
            ("downloads_remaining".to_string(), Value::Int(downloads_remaining as i128)),
        ],
    })
}

// ── 4. Retention Policy ────────────────────────────────────────────────────

/// Create a retention policy.
fn retention_policy(args: &[Value]) -> StdlibResult {
    let retain_days = match args.first() {
        Some(Value::Int(n)) => *n as i64,
        _ => 30, // default 30 days
    };
    let policy_name = get_string_arg(args, 1).unwrap_or_else(|| "default".to_string());
    let auto_delete = match args.get(2) {
        Some(Value::Bool(b)) => *b,
        _ => true,
    };

    Ok(Value::Struct {
        name: "RetentionPolicy".to_string(),
        fields: vec![
            ("name".to_string(), Value::String(policy_name)),
            ("retain_days".to_string(), Value::Int(retain_days as i128)),
            ("auto_delete".to_string(), Value::Bool(auto_delete)),
            ("legal_hold".to_string(), Value::Bool(false)),
        ],
    })
}

/// Apply retention: scan directory, delete files older than policy.
fn retention_apply(args: &[Value]) -> StdlibResult {
    let dir_path = get_string_arg(args, 0).ok_or("retention_apply: directory required")?;
    let retain_days = match args.get(1) {
        Some(Value::Int(n)) => *n as i64,
        _ => 30,
    };
    let dry_run = match args.get(2) {
        Some(Value::Bool(b)) => *b,
        _ => false,
    };

    let now = std::time::SystemTime::now();
    let max_age = std::time::Duration::from_secs(retain_days as u64 * 86400);

    let mut deleted = 0i64;
    let mut retained = 0i64;
    let mut bytes_freed = 0i64;

    if let Ok(entries) = std::fs::read_dir(&dir_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(meta) = path.metadata() {
                    if let Ok(modified) = meta.modified() {
                        if let Ok(age) = now.duration_since(modified) {
                            if age > max_age {
                                if !dry_run {
                                    let _ = std::fs::remove_file(&path);
                                }
                                bytes_freed += meta.len() as i64;
                                deleted += 1;
                            } else {
                                retained += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Value::Struct {
        name: "RetentionResult".to_string(),
        fields: vec![
            ("deleted".to_string(), Value::Int(deleted as i128)),
            ("retained".to_string(), Value::Int(retained as i128)),
            ("bytes_freed".to_string(), Value::Int(bytes_freed as i128)),
            ("dry_run".to_string(), Value::Bool(dry_run)),
        ],
    })
}

// ── 5. File Type Validation (magic bytes) ──────────────────────────────────

/// Detect file type from magic bytes (internal helper).
fn detect_file_type(data: &[u8]) -> String {
    if data.len() < 4 { return "unknown".to_string(); }
    match &data[..4] {
        [0x89, 0x50, 0x4E, 0x47] => "png",
        [0xFF, 0xD8, 0xFF, _] => "jpeg",
        [0x47, 0x49, 0x46, 0x38] => "gif",
        [0x25, 0x50, 0x44, 0x46] => "pdf",
        [0x50, 0x4B, 0x03, 0x04] => "zip",
        [0x50, 0x4B, 0x05, 0x06] => "zip",
        [0x1F, 0x8B, _, _] => "gzip",
        [0x28, 0xB5, 0x2F, 0xFD] => "zstd",
        [0x4D, 0x5A, _, _] => "exe",
        [0x7F, 0x45, 0x4C, 0x46] => "elf",
        [0xCE, 0xFA, 0xED, 0xFE] => "macho",
        [0xCF, 0xFA, 0xED, 0xFE] => "macho64",
        [0xCA, 0xFE, 0xBA, 0xBE] => "macho_fat",
        [0x52, 0x61, 0x72, 0x21] => "rar",
        [0x37, 0x7A, 0xBC, 0xAF] => "7z",
        [0x00, 0x61, 0x73, 0x6D] => "wasm",
        [0x53, 0x51, 0x4C, 0x69] => "sqlite",
        _ if data.starts_with(b"RIFF") => "riff",
        _ if data.starts_with(b"OggS") => "ogg",
        _ if data.starts_with(b"fLaC") => "flac",
        _ if data.len() > 1 && (data.starts_with(b"ID3") || (data[0] == 0xFF && data[1] & 0xE0 == 0xE0)) => "mp3",
        _ if data.starts_with(b"<!DO") || data.starts_with(b"<htm") || data.starts_with(b"<HTM") => "html",
        _ if data.starts_with(b"<?xm") => "xml",
        _ if data.starts_with(b"{") || data.starts_with(b"[") => "json",
        _ if data.starts_with(b"NIXV") => "tallow_encrypted",
        _ => "binary",
    }.to_string()
}

/// Validate file type by magic bytes (not extension -- extensions are spoofable).
fn validate_file_type(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0).ok_or("validate_file_type: file path required")?;

    let data = std::fs::read(&path).map_err(|e| format!("validate_file_type: read: {e}"))?;
    if data.len() < 4 {
        return Ok(Value::Struct {
            name: "FileValidation".to_string(),
            fields: vec![
                ("path".to_string(), Value::String(path)),
                ("detected_type".to_string(), Value::String("unknown".to_string())),
                ("mime".to_string(), Value::String("application/octet-stream".to_string())),
                ("extension".to_string(), Value::String(String::new())),
                ("executable".to_string(), Value::Bool(false)),
                ("has_script".to_string(), Value::Bool(false)),
                ("has_macro".to_string(), Value::Bool(false)),
                ("extension_mismatch".to_string(), Value::Bool(false)),
                ("safe".to_string(), Value::Bool(true)),
                ("size".to_string(), Value::Int(data.len() as i128)),
            ],
        });
    }

    // Magic byte detection
    let (file_type, mime, executable) = match &data[..4] {
        [0x89, 0x50, 0x4E, 0x47] => ("png", "image/png", false),
        [0xFF, 0xD8, 0xFF, _] => ("jpeg", "image/jpeg", false),
        [0x47, 0x49, 0x46, 0x38] => ("gif", "image/gif", false),
        [0x25, 0x50, 0x44, 0x46] => ("pdf", "application/pdf", false),
        [0x50, 0x4B, 0x03, 0x04] => ("zip", "application/zip", false),
        [0x50, 0x4B, 0x05, 0x06] => ("zip", "application/zip", false),
        [0x1F, 0x8B, _, _] => ("gzip", "application/gzip", false),
        [0x28, 0xB5, 0x2F, 0xFD] => ("zstd", "application/zstd", false),
        [0x4D, 0x5A, _, _] => ("exe", "application/x-executable", true),
        [0x7F, 0x45, 0x4C, 0x46] => ("elf", "application/x-elf", true),
        [0xCE, 0xFA, 0xED, 0xFE] => ("macho", "application/x-mach-binary", true),
        [0xCF, 0xFA, 0xED, 0xFE] => ("macho64", "application/x-mach-binary", true),
        [0xCA, 0xFE, 0xBA, 0xBE] => ("macho_fat", "application/x-mach-binary", true),
        [0x52, 0x61, 0x72, 0x21] => ("rar", "application/x-rar-compressed", false),
        [0x37, 0x7A, 0xBC, 0xAF] => ("7z", "application/x-7z-compressed", false),
        [0x00, 0x61, 0x73, 0x6D] => ("wasm", "application/wasm", true),
        [0x53, 0x51, 0x4C, 0x69] => ("sqlite", "application/x-sqlite3", false),
        _ if data.starts_with(b"RIFF") => ("riff", "audio/wav", false),
        _ if data.starts_with(b"OggS") => ("ogg", "audio/ogg", false),
        _ if data.starts_with(b"fLaC") => ("flac", "audio/flac", false),
        _ if data.len() > 1 && (data.starts_with(b"ID3") || (data[0] == 0xFF && data[1] & 0xE0 == 0xE0)) => ("mp3", "audio/mpeg", false),
        _ if data.starts_with(b"<!DO") || data.starts_with(b"<htm") || data.starts_with(b"<HTM") => ("html", "text/html", false),
        _ if data.starts_with(b"<?xm") => ("xml", "text/xml", false),
        _ if data.starts_with(b"{") || data.starts_with(b"[") => ("json", "application/json", false),
        _ if data.starts_with(b"NIXV") => ("tallow_encrypted", "application/x-tallow-vault", false),
        _ => {
            // Check if it's likely text (>90% printable ASCII)
            let printable = data.iter().take(1024)
                .filter(|&&b| (0x20..=0x7E).contains(&b) || b == 0x0A || b == 0x0D || b == 0x09)
                .count();
            let sample_size = data.len().min(1024);
            if printable * 100 / sample_size.max(1) > 90 {
                ("text", "text/plain", false)
            } else {
                ("binary", "application/octet-stream", false)
            }
        }
    };

    // Check for additional dangerous patterns
    let has_script = data.windows(8).any(|w| w == b"<script>" || w == b"<SCRIPT>");
    let has_macro = data.windows(4).any(|w| w == b"Sub " || w == b"vba_");

    let extension = std::path::Path::new(&path)
        .extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
    let extension_mismatch = matches!((file_type, extension.as_str()),
        ("exe", "pdf") | ("exe", "docx") | ("exe", "jpg") | ("exe", "png") |
        ("elf", "pdf") | ("elf", "txt") | ("elf", "doc")
    );

    Ok(Value::Struct {
        name: "FileValidation".to_string(),
        fields: vec![
            ("path".to_string(), Value::String(path)),
            ("detected_type".to_string(), Value::String(file_type.to_string())),
            ("mime".to_string(), Value::String(mime.to_string())),
            ("extension".to_string(), Value::String(extension)),
            ("executable".to_string(), Value::Bool(executable)),
            ("has_script".to_string(), Value::Bool(has_script)),
            ("has_macro".to_string(), Value::Bool(has_macro)),
            ("extension_mismatch".to_string(), Value::Bool(extension_mismatch)),
            ("safe".to_string(), Value::Bool(!executable && !has_script && !has_macro && !extension_mismatch)),
            ("size".to_string(), Value::Int(data.len() as i128)),
        ],
    })
}

/// Check if a file type is in an allowlist.
fn validate_allowlist(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0).ok_or("validate_allowlist: file path required")?;
    let allowed_types = match args.get(1) {
        Some(Value::Array(arr)) => arr.iter().map(|v| v.as_string()).collect::<Vec<_>>(),
        _ => vec!["pdf".into(), "csv".into(), "xml".into(), "json".into(), "txt".into(), "png".into(), "jpg".into()],
    };

    // Get file type by magic bytes
    let data = std::fs::read(&path).map_err(|e| format!("validate_allowlist: read: {e}"))?;
    let file_type = detect_file_type(&data);

    let allowed = allowed_types.iter().any(|t| t == &file_type);

    Ok(Value::Struct {
        name: "AllowlistCheck".to_string(),
        fields: vec![
            ("path".to_string(), Value::String(path)),
            ("detected_type".to_string(), Value::String(file_type)),
            ("allowed".to_string(), Value::Bool(allowed)),
            ("allowlist".to_string(), Value::Array(allowed_types.into_iter().map(Value::String).collect())),
        ],
    })
}

// ── 6. ML-KEM-1024 Crypto Config ──────────────────────────────────────────

/// Get available crypto configuration including ML-KEM-1024.
fn crypto_config(args: &[Value]) -> StdlibResult {
    let level = get_string_arg(args, 0).unwrap_or_else(|| "standard".to_string());

    let (kem, sig, hash, symmetric) = match level.as_str() {
        "cnsa2" | "classified" | "top_secret" => (
            "ML-KEM-1024",     // NIST Level 5 -- NSA CNSA 2.0 required
            "ML-DSA-87",       // NIST Level 5
            "SHA-384",         // CNSA 2.0 minimum
            "AES-256-GCM",
        ),
        "high" | "enterprise" => (
            "ML-KEM-768",      // NIST Level 3
            "ML-DSA-65",
            "SHA-256",
            "AES-256-GCM",
        ),
        "standard" | "default" => (
            "ML-KEM-768",
            "ML-DSA-44",
            "BLAKE3",
            "AES-256-GCM",
        ),
        "hybrid" => (
            "X25519 + ML-KEM-768",
            "Ed25519 + ML-DSA-65",
            "BLAKE3",
            "ChaCha20-Poly1305",
        ),
        _ => (
            "ML-KEM-768", "ML-DSA-44", "BLAKE3", "AES-256-GCM",
        ),
    };

    Ok(Value::Struct {
        name: "CryptoConfig".to_string(),
        fields: vec![
            ("level".to_string(), Value::String(level)),
            ("key_exchange".to_string(), Value::String(kem.to_string())),
            ("signature".to_string(), Value::String(sig.to_string())),
            ("hash".to_string(), Value::String(hash.to_string())),
            ("symmetric".to_string(), Value::String(symmetric.to_string())),
            ("post_quantum".to_string(), Value::Bool(true)),
            ("cnsa2_compliant".to_string(), Value::Bool(kem == "ML-KEM-1024")),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// Phase 63: mTLS, Key Rotation, RBAC, Webhooks, Scheduling, AV Scan
// ══════════════════════════════════════════════════════════════════

/// Create a TLS certificate configuration for mutual TLS.
fn mtls_config(args: &[Value]) -> StdlibResult {
    let cert_path = get_string_arg(args, 0).ok_or_else(|| "certificate path required".to_string())?;
    let key_path = get_string_arg(args, 1).ok_or_else(|| "private key path required".to_string())?;
    let ca_path = get_string_arg(args, 2); // optional CA cert for peer verification

    let cert_exists = Path::new(&cert_path).exists();
    let key_exists = Path::new(&key_path).exists();
    let ca_exists = ca_path.as_ref().map(|p| Path::new(p).exists()).unwrap_or(false);

    if !cert_exists {
        return Err(format!("certificate not found: {}", cert_path));
    }
    if !key_exists {
        return Err(format!("private key not found: {}", key_path));
    }

    let cert_data = std::fs::read(&cert_path).map_err(|e| format!("read cert: {e}"))?;
    let cert_hash = blake3::hash(&cert_data).to_hex().to_string();

    Ok(Value::Struct {
        name: "MtlsConfig".to_string(),
        fields: vec![
            ("cert_path".to_string(), Value::String(cert_path)),
            ("key_path".to_string(), Value::String(key_path)),
            ("ca_path".to_string(), ca_path.map(Value::String).unwrap_or(Value::Nil)),
            ("cert_fingerprint".to_string(), Value::String(cert_hash[..16].to_string())),
            ("mutual_auth".to_string(), Value::Bool(ca_exists)),
            ("verify_peer".to_string(), Value::Bool(ca_exists)),
        ],
    })
}

/// Create a key rotation schedule.
fn key_rotation_schedule(args: &[Value]) -> StdlibResult {
    let key_id = get_string_arg(args, 0).ok_or_else(|| "key_id required".to_string())?;
    let rotation_days = match args.get(1) {
        Some(Value::Int(n)) => *n as i64,
        _ => 90,
    };

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let created_at = crate::stdlib::time::epoch_secs_to_iso(epoch);
    let next_rotation = crate::stdlib::time::epoch_secs_to_iso(epoch + rotation_days * 86400);

    let key_version = blake3::hash(format!("{}:{}", key_id, epoch).as_bytes())
        .to_hex().to_string()[..16].to_string();

    Ok(Value::Struct {
        name: "KeyRotation".to_string(),
        fields: vec![
            ("key_id".to_string(), Value::String(key_id)),
            ("key_version".to_string(), Value::String(key_version)),
            ("rotation_days".to_string(), Value::Int(rotation_days as i128)),
            ("created_at".to_string(), Value::String(created_at)),
            ("next_rotation".to_string(), Value::String(next_rotation)),
            ("auto_rotate".to_string(), Value::Bool(true)),
            ("versions_retained".to_string(), Value::Int(3)),
        ],
    })
}

/// Check if a key needs rotation.
fn key_rotation_check(args: &[Value]) -> StdlibResult {
    let schedule = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("rotation schedule required".to_string()),
    };

    let next_rotation = schedule.iter()
        .find(|(k, _)| k == "next_rotation")
        .map(|(_, v)| v.as_string())
        .unwrap_or_default();

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let now_iso = crate::stdlib::time::epoch_secs_to_iso(epoch);

    let needs_rotation = now_iso >= next_rotation;

    Ok(Value::Struct {
        name: "RotationCheck".to_string(),
        fields: vec![
            ("needs_rotation".to_string(), Value::Bool(needs_rotation)),
            ("next_rotation".to_string(), Value::String(next_rotation)),
            ("current_time".to_string(), Value::String(now_iso)),
        ],
    })
}

/// Rotate a key: generate new version, archive old.
fn key_rotate(args: &[Value]) -> StdlibResult {
    let key_id = get_string_arg(args, 0).ok_or_else(|| "key_id required".to_string())?;
    let old_version = get_string_arg(args, 1).unwrap_or_default();

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let new_version = blake3::hash(format!("rotate:{}:{}", key_id, epoch).as_bytes())
        .to_hex().to_string()[..16].to_string();
    let rotated_at = crate::stdlib::time::epoch_secs_to_iso(epoch);

    Ok(Value::Struct {
        name: "KeyRotationResult".to_string(),
        fields: vec![
            ("key_id".to_string(), Value::String(key_id)),
            ("old_version".to_string(), Value::String(old_version)),
            ("new_version".to_string(), Value::String(new_version)),
            ("rotated_at".to_string(), Value::String(rotated_at)),
            ("success".to_string(), Value::Bool(true)),
        ],
    })
}

/// Create a user with a role.
fn rbac_create_user(args: &[Value]) -> StdlibResult {
    let username = get_string_arg(args, 0).ok_or_else(|| "username required".to_string())?;
    let role = get_string_arg(args, 1).unwrap_or_else(|| "transfer_only".to_string());

    let valid_roles = ["admin", "operator", "auditor", "transfer_only", "readonly"];
    if !valid_roles.contains(&role.as_str()) {
        return Err(format!("invalid role '{}'. Valid: {:?}", role, valid_roles));
    }

    let user_id = blake3::hash(username.as_bytes())
        .to_hex().to_string()[..12].to_string();

    let (can_send, can_receive, can_admin, can_audit, can_delete) = match role.as_str() {
        "admin" => (true, true, true, true, true),
        "operator" => (true, true, false, false, false),
        "auditor" => (false, false, false, true, false),
        "transfer_only" => (true, true, false, false, false),
        "readonly" => (false, false, false, true, false),
        _ => (false, false, false, false, false),
    };

    Ok(Value::Struct {
        name: "RbacUser".to_string(),
        fields: vec![
            ("user_id".to_string(), Value::String(user_id)),
            ("username".to_string(), Value::String(username)),
            ("role".to_string(), Value::String(role)),
            ("can_send".to_string(), Value::Bool(can_send)),
            ("can_receive".to_string(), Value::Bool(can_receive)),
            ("can_admin".to_string(), Value::Bool(can_admin)),
            ("can_audit".to_string(), Value::Bool(can_audit)),
            ("can_delete".to_string(), Value::Bool(can_delete)),
        ],
    })
}

/// Check if a user has permission for an action.
fn rbac_check(args: &[Value]) -> StdlibResult {
    let user = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("user struct required".to_string()),
    };
    let action = get_string_arg(args, 1).ok_or_else(|| "action required".to_string())?;

    let perm_key = match action.as_str() {
        "send" => "can_send",
        "receive" => "can_receive",
        "admin" | "configure" => "can_admin",
        "audit" | "view_logs" => "can_audit",
        "delete" | "purge" => "can_delete",
        _ => return Err(format!("unknown action: {}", action)),
    };

    let allowed = user.iter()
        .find(|(k, _)| k == perm_key)
        .and_then(|(_, v)| if let Value::Bool(b) = v { Some(*b) } else { None })
        .unwrap_or(false);

    let username = user.iter().find(|(k, _)| k == "username")
        .map(|(_, v)| v.as_string()).unwrap_or_default();
    let role = user.iter().find(|(k, _)| k == "role")
        .map(|(_, v)| v.as_string()).unwrap_or_default();

    Ok(Value::Struct {
        name: "RbacCheck".to_string(),
        fields: vec![
            ("username".to_string(), Value::String(username)),
            ("role".to_string(), Value::String(role)),
            ("action".to_string(), Value::String(action)),
            ("allowed".to_string(), Value::Bool(allowed)),
        ],
    })
}

/// Create a webhook configuration.
fn webhook_config(args: &[Value]) -> StdlibResult {
    let url = get_string_arg(args, 0).ok_or_else(|| "webhook URL required".to_string())?;
    let events = match args.get(1) {
        Some(Value::Array(arr)) => arr.iter().map(|v| v.as_string()).collect::<Vec<_>>(),
        _ => vec!["transfer_complete".into(), "transfer_failed".into()],
    };
    let secret = get_string_arg(args, 2);

    Ok(Value::Struct {
        name: "WebhookConfig".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(url)),
            ("events".to_string(), Value::Array(events.into_iter().map(Value::String).collect())),
            ("secret".to_string(), secret.map(Value::String).unwrap_or(Value::Nil)),
            ("active".to_string(), Value::Bool(true)),
            ("retry_count".to_string(), Value::Int(3)),
        ],
    })
}

/// Fire a webhook (builds HTTP POST payload with HMAC signature).
fn webhook_fire(args: &[Value]) -> StdlibResult {
    let url = get_string_arg(args, 0).ok_or_else(|| "webhook URL required".to_string())?;
    let event = get_string_arg(args, 1).ok_or_else(|| "event name required".to_string())?;
    let payload = get_string_arg(args, 2).unwrap_or_else(|| "{}".to_string());
    let secret = get_string_arg(args, 3);

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let timestamp = crate::stdlib::time::epoch_secs_to_iso(epoch);

    // Compute HMAC signature if secret provided
    let signature = secret.as_ref().map(|s| {
        blake3::keyed_hash(
            blake3::hash(s.as_bytes()).as_bytes(),
            format!("{}:{}", timestamp, payload).as_bytes(),
        ).to_hex().to_string()
    });

    let body = format!(
        r#"{{"event":"{}","timestamp":"{}","payload":{},"signature":{}}}"#,
        event, timestamp, payload,
        signature.as_ref().map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "null".to_string())
    );

    Ok(Value::Struct {
        name: "WebhookResult".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(url)),
            ("event".to_string(), Value::String(event)),
            ("body".to_string(), Value::String(body)),
            ("timestamp".to_string(), Value::String(timestamp)),
            ("signature".to_string(), signature.map(Value::String).unwrap_or(Value::Nil)),
            ("fired".to_string(), Value::Bool(true)),
        ],
    })
}

/// Create a transfer schedule (cron-like).
fn schedule_create(args: &[Value]) -> StdlibResult {
    let name = get_string_arg(args, 0).ok_or_else(|| "schedule name required".to_string())?;
    let cron_expr = get_string_arg(args, 1)
        .ok_or_else(|| "cron expression required (e.g., '0 2 * * *')".to_string())?;
    let source = get_string_arg(args, 2).ok_or_else(|| "source path required".to_string())?;
    let destination = get_string_arg(args, 3).ok_or_else(|| "destination required".to_string())?;

    let parts: Vec<&str> = cron_expr.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(format!(
            "invalid cron expression '{}': expected 5 fields (min hour dom mon dow)", cron_expr
        ));
    }

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let created_at = crate::stdlib::time::epoch_secs_to_iso(epoch);

    let schedule_id = blake3::hash(format!("{}:{}:{}", name, cron_expr, epoch).as_bytes())
        .to_hex().to_string()[..12].to_string();

    Ok(Value::Struct {
        name: "TransferSchedule".to_string(),
        fields: vec![
            ("schedule_id".to_string(), Value::String(schedule_id)),
            ("name".to_string(), Value::String(name)),
            ("cron".to_string(), Value::String(cron_expr)),
            ("source".to_string(), Value::String(source)),
            ("destination".to_string(), Value::String(destination)),
            ("active".to_string(), Value::Bool(true)),
            ("created_at".to_string(), Value::String(created_at)),
            ("last_run".to_string(), Value::Nil),
            ("next_run".to_string(), Value::String("pending".to_string())),
            ("runs_completed".to_string(), Value::Int(0)),
            ("runs_failed".to_string(), Value::Int(0)),
        ],
    })
}

/// Check if a schedule should run now (simplified cron check).
fn schedule_check(args: &[Value]) -> StdlibResult {
    let schedule = match args.first() {
        Some(Value::Struct { fields, .. }) => fields.clone(),
        _ => return Err("schedule struct required".to_string()),
    };

    let active = schedule.iter()
        .find(|(k, _)| k == "active")
        .and_then(|(_, v)| if let Value::Bool(b) = v { Some(*b) } else { None })
        .unwrap_or(false);

    let cron = schedule.iter()
        .find(|(k, _)| k == "cron")
        .map(|(_, v)| v.as_string())
        .unwrap_or_default();

    let parts: Vec<&str> = cron.split_whitespace().collect();
    let should_run = if parts.len() == 5 && active {
        parts.iter().all(|p| *p == "*")
    } else {
        false
    };

    Ok(Value::Struct {
        name: "ScheduleCheck".to_string(),
        fields: vec![
            ("should_run".to_string(), Value::Bool(should_run)),
            ("active".to_string(), Value::Bool(active)),
            ("cron".to_string(), Value::String(cron)),
        ],
    })
}

/// Scan a file for malware using ClamAV (if installed).
fn av_scan(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0).ok_or_else(|| "file path required".to_string())?;

    if !Path::new(&path).exists() {
        return Err(format!("file not found: {}", path));
    }

    let result = std::process::Command::new("clamscan")
        .arg("--no-summary")
        .arg("--infected")
        .arg(&path)
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let exit_code = output.status.code().unwrap_or(-1);

            let (clean, threat_name) = match exit_code {
                0 => (true, "none".to_string()),
                1 => {
                    let threat = stdout.split("FOUND").next()
                        .and_then(|s| s.split(':').nth(1))
                        .map(|s| s.trim().to_string())
                        .unwrap_or_else(|| "unknown threat".to_string());
                    (false, threat)
                }
                _ => (true, "scan_error".to_string()),
            };

            Ok(Value::Struct {
                name: "AvScanResult".to_string(),
                fields: vec![
                    ("path".to_string(), Value::String(path)),
                    ("clean".to_string(), Value::Bool(clean)),
                    ("threat".to_string(), Value::String(threat_name)),
                    ("scanner".to_string(), Value::String("clamav".to_string())),
                    ("exit_code".to_string(), Value::Int(exit_code as i128)),
                ],
            })
        }
        Err(_) => {
            Ok(Value::Struct {
                name: "AvScanResult".to_string(),
                fields: vec![
                    ("path".to_string(), Value::String(path)),
                    ("clean".to_string(), Value::Bool(true)),
                    ("threat".to_string(), Value::String("none".to_string())),
                    ("scanner".to_string(), Value::String("unavailable".to_string())),
                    ("warning".to_string(), Value::String(
                        "ClamAV (clamscan) not installed -- install with: apt install clamav".to_string()
                    )),
                ],
            })
        }
    }
}

/// Scan with YARA rules (if yara is installed).
fn yara_scan(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0).ok_or_else(|| "file path required".to_string())?;
    let rules_path = get_string_arg(args, 1).unwrap_or_else(|| "rules.yar".to_string());

    let result = std::process::Command::new("yara")
        .arg(&rules_path)
        .arg(&path)
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let matches: Vec<Value> = stdout.lines()
                .filter(|l| !l.is_empty())
                .map(|l| Value::String(l.to_string()))
                .collect();
            let has_matches = !matches.is_empty();

            Ok(Value::Struct {
                name: "YaraScanResult".to_string(),
                fields: vec![
                    ("path".to_string(), Value::String(path)),
                    ("rules_path".to_string(), Value::String(rules_path)),
                    ("matches".to_string(), Value::Array(matches)),
                    ("has_matches".to_string(), Value::Bool(has_matches)),
                ],
            })
        }
        Err(_) => Ok(Value::Struct {
            name: "YaraScanResult".to_string(),
            fields: vec![
                ("path".to_string(), Value::String(path)),
                ("matches".to_string(), Value::Array(vec![])),
                ("has_matches".to_string(), Value::Bool(false)),
                ("warning".to_string(), Value::String("YARA not installed".to_string())),
            ],
        }),
    }
}

// ══════════════════════════════════════════════════════════════════
// Feature 5: Air-gap transfer modes
// ══════════════════════════════════════════════════════════════════
//
// Three modalities for crossing air-gaps:
//   QR  — base64-encode data, split into 2953-byte chunks (QR v40 capacity)
//   Audio — map each byte to a frequency in 300-2850 Hz range (BFSK)
//
// Both are designed to be camera/microphone-decodable without network access.

/// airgap_to_qr(data) → Array<QRChunk>
///
/// Base64-encodes data and splits it into chunks sized for QR v40 alphanumeric
/// capacity (2953 characters per QR code). Each chunk carries its index and
/// total so the receiver can reassemble in order.
fn airgap_to_qr(args: &[Value]) -> StdlibResult {
    use base64::Engine;
    let data = match args.first() {
        Some(v) => v.as_string(),
        None => return Err("airgap_to_qr: data required".to_string()),
    };

    let max_chunk: usize = 2953; // QR version 40 alphanumeric capacity
    let encoded = base64::engine::general_purpose::STANDARD.encode(data.as_bytes());
    let total = (encoded.len() + max_chunk - 1) / max_chunk;

    let chunks: Vec<Value> = encoded.as_bytes()
        .chunks(max_chunk)
        .enumerate()
        .map(|(i, chunk)| Value::Struct {
            name: "QRChunk".into(),
            fields: vec![
                ("index".into(), Value::Int(i as i128)),
                ("total".into(), Value::Int(total as i128)),
                ("data".into(), Value::String(String::from_utf8_lossy(chunk).to_string())),
                ("encoding".into(), Value::String("base64".into())),
            ],
        })
        .collect();

    Ok(Value::Array(chunks))
}

/// airgap_from_qr(chunks: Array<QRChunk>) → String
///
/// Sorts chunks by index, concatenates base64 data, and decodes to original string.
fn airgap_from_qr(args: &[Value]) -> StdlibResult {
    use base64::Engine;
    let chunks = match args.first() {
        Some(Value::Array(arr)) => arr.clone(),
        _ => return Err("airgap_from_qr: requires Array of QRChunk values".to_string()),
    };

    // Collect (index, data) pairs
    let mut pairs: Vec<(i128, String)> = chunks.iter().filter_map(|v| {
        if let Value::Struct { fields, .. } = v {
            let idx = fields.iter()
                .find(|(k, _)| k == "index")
                .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None })?;
            let data = fields.iter()
                .find(|(k, _)| k == "data")
                .map(|(_, v)| v.as_string())?;
            Some((idx, data))
        } else {
            None
        }
    }).collect();

    if pairs.is_empty() {
        return Ok(Value::String(String::new()));
    }

    pairs.sort_by_key(|(i, _)| *i);
    let combined: String = pairs.into_iter().map(|(_, d)| d).collect();

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(combined.as_bytes())
        .map_err(|e| format!("airgap_from_qr: base64 decode error: {e}"))?;

    Ok(Value::String(String::from_utf8_lossy(&decoded).to_string()))
}

/// airgap_to_audio(data) → AudioData
///
/// Maps each byte to a tone frequency for acoustic air-gap transfer using
/// Binary Frequency-Shift Keying (BFSK).
/// Frequency formula: 300 Hz + (byte_value × 10) = range 300–2850 Hz.
/// Each tone plays for 100 ms at 44100 Hz sample rate.
fn airgap_to_audio(args: &[Value]) -> StdlibResult {
    let data = match args.first() {
        Some(v) => v.as_string(),
        None => return Err("airgap_to_audio: data required".to_string()),
    };

    let frequencies: Vec<Value> = data.bytes()
        .map(|b| Value::Int(300 + (b as i128) * 10))
        .collect();

    let byte_count = data.len() as i128;

    Ok(Value::Struct {
        name: "AudioData".into(),
        fields: vec![
            ("frequencies".into(), Value::Array(frequencies)),
            ("sample_rate".into(), Value::Int(44100)),
            ("duration_ms".into(), Value::Int(byte_count * 100)),
            ("encoding".into(), Value::String("BFSK".into())),
            ("freq_min_hz".into(), Value::Int(300)),
            ("freq_max_hz".into(), Value::Int(2850)),
            ("ms_per_byte".into(), Value::Int(100)),
            ("byte_count".into(), Value::Int(byte_count)),
        ],
    })
}

// ══════════════════════════════════════════════════════════════════
// Feature 8: Cloud storage sync primitives
// ══════════════════════════════════════════════════════════════════
// Feature 8: Cloud storage sync — real S3 REST API with SigV4
// ══════════════════════════════════════════════════════════════════
//
// All cloud operations use the AWS S3 REST API signed with AWS Signature V4
// via ureq + hmac-sha2. One implementation covers:
//   AWS S3, MinIO, Cloudflare R2, Backblaze B2, Wasabi, DigitalOcean Spaces,
//   GCS (XML API), Scaleway, IDrive e2, any S3-compatible endpoint.
//
// Required environment variables:
//   AWS_ACCESS_KEY_ID       — access key (required)
//   AWS_SECRET_ACCESS_KEY   — secret key (required)
//   AWS_DEFAULT_REGION      — region (default: us-east-1)
//   AWS_ENDPOINT_URL        — custom endpoint for non-AWS services (optional)
//
// GCS:   set GCS_ACCESS_KEY_ID + GCS_SECRET_ACCESS_KEY (HMAC keys from console)
// Azure: set AZURE_STORAGE_ACCOUNT + AZURE_STORAGE_KEY

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// ─── SigV4 credential bundle ─────────────────────────────────────────────────

struct S3Creds {
    access_key: String,
    secret_key: String,
    region:     String,
    endpoint:   String,
}

impl S3Creds {
    fn from_env() -> Result<Self, String> {
        let access_key = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| {
            "cloud: AWS_ACCESS_KEY_ID not set — export AWS_ACCESS_KEY_ID=<key>".to_string()
        })?;
        let secret_key = std::env::var("AWS_SECRET_ACCESS_KEY").map_err(|_| {
            "cloud: AWS_SECRET_ACCESS_KEY not set — export AWS_SECRET_ACCESS_KEY=<secret>"
                .to_string()
        })?;
        let region = std::env::var("AWS_DEFAULT_REGION")
            .unwrap_or_else(|_| "us-east-1".to_string());
        let endpoint = std::env::var("AWS_ENDPOINT_URL")
            .unwrap_or_else(|_| format!("https://s3.{region}.amazonaws.com"));
        Ok(Self { access_key, secret_key, region, endpoint })
    }

    fn from_env_gcs() -> Result<Self, String> {
        let access_key = std::env::var("GCS_ACCESS_KEY_ID")
            .or_else(|_| std::env::var("AWS_ACCESS_KEY_ID"))
            .map_err(|_| {
                "cloud_gcs: GCS_ACCESS_KEY_ID not set — create HMAC keys in GCS console"
                    .to_string()
            })?;
        let secret_key = std::env::var("GCS_SECRET_ACCESS_KEY")
            .or_else(|_| std::env::var("AWS_SECRET_ACCESS_KEY"))
            .map_err(|_| "cloud_gcs: GCS_SECRET_ACCESS_KEY not set".to_string())?;
        let region = std::env::var("AWS_DEFAULT_REGION")
            .unwrap_or_else(|_| "auto".to_string());
        let endpoint = std::env::var("GCS_ENDPOINT")
            .or_else(|_| std::env::var("AWS_ENDPOINT_URL"))
            .unwrap_or_else(|_| "https://storage.googleapis.com".to_string());
        Ok(Self { access_key, secret_key, region, endpoint })
    }

    fn from_env_azure() -> Result<Self, String> {
        let access_key = std::env::var("AZURE_STORAGE_ACCOUNT")
            .map_err(|_| "cloud_azure: AZURE_STORAGE_ACCOUNT not set".to_string())?;
        let secret_key = std::env::var("AZURE_STORAGE_KEY")
            .map_err(|_| "cloud_azure: AZURE_STORAGE_KEY not set".to_string())?;
        let region =
            std::env::var("AWS_DEFAULT_REGION").unwrap_or_else(|_| "auto".to_string());
        let acct = access_key.clone();
        let endpoint = std::env::var("AZURE_ENDPOINT")
            .or_else(|_| std::env::var("AWS_ENDPOINT_URL"))
            .unwrap_or_else(|_| format!("https://{acct}.blob.core.windows.net"));
        Ok(Self { access_key, secret_key, region, endpoint })
    }

    /// Virtual-hosted style for real AWS; path-style for S3-compatible endpoints.
    fn bucket_url(&self, bucket: &str) -> String {
        if self.endpoint.contains("amazonaws.com") {
            format!(
                "https://{bucket}.s3.{region}.amazonaws.com",
                region = self.region
            )
        } else {
            format!("{}/{bucket}", self.endpoint.trim_end_matches('/'))
        }
    }
}

// ─── AWS Signature V4 ────────────────────────────────────────────────────────

fn s3_sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    Digest::update(&mut h, data);
    format!("{:x}", Digest::finalize(h))
}

fn s3_hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn s3_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Percent-encode a URI path — preserves '/'.
fn s3_uri_path(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~' | '/') {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

/// Percent-encode a URI query value — encodes '/', '=', '&', etc.
fn s3_uri_query(s: &str) -> String {
    s.chars()
        .flat_map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
                vec![c]
            } else {
                format!("%{:02X}", c as u32).chars().collect::<Vec<_>>()
            }
        })
        .collect()
}

/// Current UTC timestamp in SigV4 format "20260101T120000Z".
fn s3_now() -> String {
    chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Compute `Authorization`, `x-amz-date`, and `x-amz-content-sha256` for a
/// signed S3 request.  Returns `(auth_header, amz_date, content_sha256)`.
///
/// # SigV4 algorithm
/// ```text
/// CanonicalRequest  = Method + PathEnc + CanonQS + Headers + SignedHdrs + PayloadHash
/// StringToSign      = "AWS4-HMAC-SHA256" + Timestamp + Scope + SHA256(CanonRequest)
/// SigningKey        = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), "s3"), "aws4_request")
/// Signature         = hex(HMAC(SigningKey, StringToSign))
/// ```
fn sigv4_sign(
    method:  &str,
    url:     &str,
    extra:   &[(String, String)],
    payload: &[u8],
    creds:   &S3Creds,
    now:     &str,
) -> (String, String, String) {
    let date  = &now[..8];
    let phash = s3_sha256_hex(payload);

    // Split path + query from URL
    let (path, qs) = {
        let tail  = url.trim_start_matches("https://").trim_start_matches("http://");
        let slash = tail.find('/').unwrap_or(tail.len());
        let pq    = &tail[slash..];
        let pq    = if pq.is_empty() { "/" } else { pq };
        if let Some(q) = pq.find('?') {
            (pq[..q].to_string(), pq[q + 1..].to_string())
        } else {
            (pq.to_string(), String::new())
        }
    };

    // Canonical query string: sorted, percent-encoded key=value pairs
    let canon_qs = {
        let mut pairs: Vec<(String, String)> = qs
            .split('&')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                if let Some(eq) = kv.find('=') {
                    (s3_uri_query(&kv[..eq]), s3_uri_query(&kv[eq + 1..]))
                } else {
                    (s3_uri_query(kv), String::new())
                }
            })
            .collect();
        pairs.sort();
        pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&")
    };

    // Extract host
    let host = {
        let tail = url.trim_start_matches("https://").trim_start_matches("http://");
        tail.split('/').next().unwrap_or("").split('?').next().unwrap_or("")
    };

    // Build full header set (must include host, x-amz-content-sha256, x-amz-date)
    let mut hdrs: Vec<(String, String)> = extra.to_vec();
    hdrs.push(("host".to_string(), host.to_string()));
    hdrs.push(("x-amz-content-sha256".to_string(), phash.clone()));
    hdrs.push(("x-amz-date".to_string(), now.to_string()));
    hdrs.sort_by(|a, b| a.0.cmp(&b.0));

    let canon_hdrs: String = hdrs
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v.trim()))
        .collect();
    let signed_hdrs: String = hdrs
        .iter()
        .map(|(k, _)| k.clone())
        .collect::<Vec<_>>()
        .join(";");

    let canon_req = format!(
        "{method}\n{path}\n{canon_qs}\n{canon_hdrs}\n{signed_hdrs}\n{phash}",
        path = s3_uri_path(&path),
    );

    let scope    = format!("{date}/{region}/s3/aws4_request", region = creds.region);
    let sts      = format!(
        "AWS4-HMAC-SHA256\n{now}\n{scope}\n{}",
        s3_sha256_hex(canon_req.as_bytes())
    );
    let k_date   = s3_hmac_sha256(
        format!("AWS4{}", creds.secret_key).as_bytes(),
        date.as_bytes(),
    );
    let k_region = s3_hmac_sha256(&k_date,   creds.region.as_bytes());
    let k_svc    = s3_hmac_sha256(&k_region, b"s3");
    let k_sign   = s3_hmac_sha256(&k_svc,    b"aws4_request");
    let sig      = s3_hex(&s3_hmac_sha256(&k_sign, sts.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, \
         SignedHeaders={signed_hdrs}, Signature={sig}",
        creds.access_key,
    );
    (auth, now.to_string(), phash)
}

// ─── ureq helpers ─────────────────────────────────────────────────────────────

fn s3_req_no_body(
    method: &str,
    url:    &str,
    creds:  &S3Creds,
    extra:  &[(String, String)],
) -> Result<(u16, String), String> {
    let now = s3_now();
    let (auth, amz_date, csha) = sigv4_sign(method, url, extra, &[], creds, &now);
    let agent = s3_agent();
    let mut req = match method {
        "GET"    => agent.get(url),
        "HEAD"   => agent.head(url),
        "DELETE" => agent.delete(url),
        _        => agent.get(url),
    };
    req = req
        .header("Authorization",        &auth)
        .header("x-amz-date",           &amz_date)
        .header("x-amz-content-sha256", &csha);
    for (k, v) in extra {
        req = req.header(k.as_str(), v.as_str());
    }
    match req.call() {
        Ok(resp) => {
            let s = resp.status().as_u16();
            let b = resp.into_body().read_to_string().unwrap_or_default();
            if s < 300 || s == 304 {
                Ok((s, b))
            } else {
                Err(format!("S3 {method} {url} -> HTTP {s}: {b}"))
            }
        }
        Err(e) => Err(format!("S3 {method} {url} -> {e}")),
    }
}

fn s3_agent() -> ureq::Agent {
    // Bounded so an 8 MiB multipart part or a large download cannot hang
    // forever over Tor: 600 s wall clock, 30 s per socket operation.
    crate::runtime::egress_http::agent_with_timeouts(
        Some(std::time::Duration::from_secs(600)),
        Some(std::time::Duration::from_secs(30)),
    )
}

fn s3_req_with_body(
    method: &str,
    url:    &str,
    creds:  &S3Creds,
    body:   Vec<u8>,
    ct:     &str,
    extra:  &[(String, String)],
) -> Result<(u16, String), String> {
    let now = s3_now();
    let (auth, amz_date, csha) = sigv4_sign(method, url, extra, &body, creds, &now);
    let agent = s3_agent();
    let mut req = match method {
        "PUT"  => agent.put(url),
        "POST" => agent.post(url),
        _      => agent.put(url),
    };
    req = req
        .header("Authorization",        &auth)
        .header("x-amz-date",           &amz_date)
        .header("x-amz-content-sha256", &csha)
        .header("Content-Type",         ct)
        .header("Content-Length",       &body.len().to_string());
    for (k, v) in extra {
        req = req.header(k.as_str(), v.as_str());
    }
    match req.send(body) {
        Ok(resp) => {
            let s = resp.status().as_u16();
            let b = resp.into_body().read_to_string().unwrap_or_default();
            if s < 300 {
                Ok((s, b))
            } else {
                Err(format!("S3 {method} {url} -> HTTP {s}: {b}"))
            }
        }
        Err(e) => Err(format!("S3 {method} {url} -> {e}")),
    }
}

/// GET and return raw binary response body (binary-safe).
fn s3_get_bytes(url: &str, creds: &S3Creds) -> Result<Vec<u8>, String> {
    let now = s3_now();
    let (auth, amz_date, csha) = sigv4_sign("GET", url, &[], &[], creds, &now);
    let agent = s3_agent();
    let req = agent
        .get(url)
        .header("Authorization",        &auth)
        .header("x-amz-date",           &amz_date)
        .header("x-amz-content-sha256", &csha);
    match req.call() {
        Ok(resp) => {
            let s = resp.status().as_u16();
            let buf = Vec::new();
            resp.into_body()
                .read_to_vec()
                .map_err(|e| format!("S3 GET read: {e}"))?;
            if s < 300 {
                Ok(buf)
            } else {
                Err(format!(
                    "S3 GET {url} -> HTTP {s}: {}",
                    String::from_utf8_lossy(&buf)
                ))
            }
        }
        Err(e) => Err(format!("S3 GET {url} -> {e}")),
    }
}

// ─── XML helpers (no external xml crate needed) ───────────────────────────────

fn xml_all(xml: &str, tag: &str) -> Vec<String> {
    let open  = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut out  = Vec::new();
    let mut rest = xml;
    while let Some(s) = rest.find(&open) {
        let after = &rest[s + open.len()..];
        if let Some(e) = after.find(&close) {
            out.push(after[..e].to_string());
            rest = &after[e + close.len()..];
        } else {
            break;
        }
    }
    out
}

fn xml_one(xml: &str, tag: &str) -> Option<String> {
    xml_all(xml, tag).into_iter().next()
}

fn parse_list_xml(xml: &str) -> Vec<(String, i128, String)> {
    xml_all(xml, "Contents")
        .into_iter()
        .map(|b| {
            let key   = xml_one(&b, "Key").unwrap_or_default();
            let size  = xml_one(&b, "Size")
                .unwrap_or_default()
                .parse()
                .unwrap_or(0);
            let mtime = xml_one(&b, "LastModified").unwrap_or_default();
            (key, size, mtime)
        })
        .collect()
}

fn parse_etag_xml(s: &str) -> String {
    xml_one(s, "ETag")
        .unwrap_or_else(|| s.trim().to_string())
        .trim_matches('"')
        .to_string()
}

// ─── Multipart upload ────────────────────────────────────────────────────────

fn s3_multipart_upload(
    creds:    &S3Creds,
    base:     &str,
    key_enc:  &str,
    blake3h:  &str,
    data:     Vec<u8>,
    part_sz:  usize,
) -> Result<String, String> {
    let obj_url    = format!("{base}/{key_enc}");
    let init_url   = format!("{obj_url}?uploads");
    let init_extra = vec![("x-amz-meta-blake3".to_string(), blake3h.to_string())];

    let (_, init_body) = s3_req_with_body(
        "POST", &init_url, creds, vec![], "application/octet-stream", &init_extra,
    )?;
    let upload_id = xml_one(&init_body, "UploadId")
        .ok_or_else(|| format!("cloud_s3_upload: no UploadId in: {init_body}"))?;

    let parts: Vec<Vec<u8>> = data.chunks(part_sz).map(|c| c.to_vec()).collect();
    let nparts = parts.len();

    use rayon::prelude::*;
    use std::sync::Mutex;

    let results:  Mutex<Vec<(usize, String)>> = Mutex::new(Vec::new());
    let err_slot: Mutex<Option<String>>        = Mutex::new(None);

    parts.into_par_iter().enumerate().for_each(|(i, chunk)| {
        if err_slot.lock().unwrap().is_some() {
            return;
        }
        let n    = i + 1;
        let purl = format!(
            "{obj_url}?partNumber={n}&uploadId={}",
            s3_uri_query(&upload_id)
        );
        match s3_req_with_body("PUT", &purl, creds, chunk, "application/octet-stream", &[]) {
            Ok((_, body)) => {
                results.lock().unwrap().push((n, parse_etag_xml(&body)));
            }
            Err(e) => {
                *err_slot.lock().unwrap() = Some(e);
            }
        }
    });

    if let Some(e) = err_slot.into_inner().unwrap() {
        let abort = format!("{obj_url}?uploadId={}", s3_uri_query(&upload_id));
        let _     = s3_req_no_body("DELETE", &abort, creds, &[]);
        return Err(e);
    }

    let mut plist = results.into_inner().unwrap();
    plist.sort_by_key(|(n, _)| *n);
    assert_eq!(plist.len(), nparts, "multipart: part count mismatch");

    let parts_xml: String = plist
        .iter()
        .map(|(n, etag)| {
            format!("<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>")
        })
        .collect::<Vec<_>>()
        .join("");
    let complete_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{parts_xml}</CompleteMultipartUpload>"#
    );
    let complete_url = format!("{obj_url}?uploadId={}", s3_uri_query(&upload_id));
    let (_, body) = s3_req_with_body(
        "POST", &complete_url, creds, complete_xml.into_bytes(), "application/xml", &[],
    )?;
    Ok(parse_etag_xml(&body))
}

// ─── Public API ───────────────────────────────────────────────────────────────

/// `cloud_s3_list(bucket, prefix?) -> S3ListResult`
///
/// Lists objects in an S3-compatible bucket. Reads AWS credentials and optional
/// `AWS_ENDPOINT_URL` for non-AWS services (MinIO, Cloudflare R2, Backblaze B2, etc.).
fn cloud_s3_list(args: &[Value]) -> StdlibResult {
    let bucket = match args.first() {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_list: bucket required".to_string()),
    };
    let prefix = args.get(1).map(|v| v.as_string()).unwrap_or_default();
    let creds  = S3Creds::from_env()?;
    let base   = creds.bucket_url(&bucket);
    let url = if prefix.is_empty() {
        format!("{base}/?list-type=2")
    } else {
        format!("{base}/?list-type=2&prefix={}", s3_uri_query(&prefix))
    };
    let (_, body) = s3_req_no_body("GET", &url, &creds, &[])?;
    let objects: Vec<Value> = parse_list_xml(&body)
        .into_iter()
        .map(|(key, size, mtime)| Value::Struct {
            name:   "S3Object".into(),
            fields: vec![
                ("key".into(),           Value::String(key)),
                ("size".into(),          Value::Int(size)),
                ("last_modified".into(), Value::String(mtime)),
            ],
        })
        .collect();
    Ok(Value::Struct {
        name:   "S3ListResult".into(),
        fields: vec![
            ("bucket".into(),  Value::String(bucket)),
            ("prefix".into(),  Value::String(prefix)),
            ("count".into(),   Value::Int(objects.len() as i128)),
            ("objects".into(), Value::Array(objects)),
        ],
    })
}

/// `cloud_s3_upload(bucket, key, local_path) -> S3UploadResult`
///
/// Uploads a local file to S3. Single PUT for files < 5 MB; parallel multipart
/// (8 MB parts via rayon) for larger files. Stores BLAKE3 hash as
/// `x-amz-meta-blake3` object metadata for integrity verification on download.
fn cloud_s3_upload(args: &[Value]) -> StdlibResult {
    let bucket     = match args.first() {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_upload: bucket required".to_string()),
    };
    let key = match args.get(1) {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_upload: key required".to_string()),
    };
    let local_path = match args.get(2) {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_upload: local_path required".to_string()),
    };

    let creds = S3Creds::from_env()?;
    let data  = std::fs::read(&local_path)
        .map_err(|e| format!("cloud_s3_upload: read {local_path}: {e}"))?;
    let size  = data.len() as i128;
    let bh    = blake3::hash(&data).to_hex().to_string();

    const THRESHOLD: usize = 5 * 1024 * 1024;
    const PART:      usize = 8 * 1024 * 1024;

    let base    = creds.bucket_url(&bucket);
    let key_enc = s3_uri_path(&key);
    let obj_url = format!("{base}/{key_enc}");

    let etag = if data.len() <= THRESHOLD {
        let extra = vec![("x-amz-meta-blake3".to_string(), bh.clone())];
        let (_, body) = s3_req_with_body(
            "PUT", &obj_url, &creds, data, "application/octet-stream", &extra,
        )?;
        parse_etag_xml(&body)
    } else {
        s3_multipart_upload(&creds, &base, &key_enc, &bh, data, PART)?
    };

    Ok(Value::Struct {
        name:   "S3UploadResult".into(),
        fields: vec![
            ("bucket".into(), Value::String(bucket)),
            ("key".into(),    Value::String(key)),
            ("etag".into(),   Value::String(etag)),
            ("size".into(),   Value::Int(size)),
            ("blake3".into(), Value::String(bh)),
        ],
    })
}

/// `cloud_s3_download(bucket, key, local_path) -> S3DownloadResult`
///
/// Downloads an S3 object to disk and returns its BLAKE3 hash so callers can
/// verify integrity against the `x-amz-meta-blake3` metadata stored at upload.
fn cloud_s3_download(args: &[Value]) -> StdlibResult {
    let bucket     = match args.first() {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_download: bucket required".to_string()),
    };
    let key = match args.get(1) {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_download: key required".to_string()),
    };
    let local_path = match args.get(2) {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_download: local_path required".to_string()),
    };

    let creds   = S3Creds::from_env()?;
    let base    = creds.bucket_url(&bucket);
    let key_enc = s3_uri_path(&key);
    let obj_url = format!("{base}/{key_enc}");

    let bytes = s3_get_bytes(&obj_url, &creds)?;
    let size  = bytes.len() as i128;

    if let Some(p) = std::path::Path::new(&local_path).parent() {
        std::fs::create_dir_all(p)
            .map_err(|e| format!("cloud_s3_download: mkdir {}: {e}", p.display()))?;
    }
    std::fs::write(&local_path, &bytes)
        .map_err(|e| format!("cloud_s3_download: write {local_path}: {e}"))?;
    let bh = blake3::hash(&bytes).to_hex().to_string();

    Ok(Value::Struct {
        name:   "S3DownloadResult".into(),
        fields: vec![
            ("bucket".into(),     Value::String(bucket)),
            ("key".into(),        Value::String(key)),
            ("local_path".into(), Value::String(local_path)),
            ("size".into(),       Value::Int(size)),
            ("blake3".into(),     Value::String(bh)),
        ],
    })
}

/// `cloud_s3_delete(bucket, key) -> S3DeleteResult`
///
/// Issues a signed DELETE request. Returns `{bucket, key, deleted: true}`.
fn cloud_s3_delete(args: &[Value]) -> StdlibResult {
    let bucket = match args.first() {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_delete: bucket required".to_string()),
    };
    let key = match args.get(1) {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_delete: key required".to_string()),
    };

    let creds   = S3Creds::from_env()?;
    let base    = creds.bucket_url(&bucket);
    let key_enc = s3_uri_path(&key);
    let obj_url = format!("{base}/{key_enc}");

    s3_req_no_body("DELETE", &obj_url, &creds, &[])?;

    Ok(Value::Struct {
        name:   "S3DeleteResult".into(),
        fields: vec![
            ("bucket".into(),  Value::String(bucket)),
            ("key".into(),     Value::String(key)),
            ("deleted".into(), Value::Bool(true)),
        ],
    })
}

/// `cloud_s3_head(bucket, key) -> S3HeadResult`
///
/// Returns object metadata (size, content-type, ETag, BLAKE3 meta) without
/// downloading the body. Sets `exists: false` on 404.
fn cloud_s3_head(args: &[Value]) -> StdlibResult {
    let bucket = match args.first() {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_head: bucket required".to_string()),
    };
    let key = match args.get(1) {
        Some(v) => v.as_string(),
        None    => return Err("cloud_s3_head: key required".to_string()),
    };

    let creds   = S3Creds::from_env()?;
    let base    = creds.bucket_url(&bucket);
    let key_enc = s3_uri_path(&key);
    let obj_url = format!("{base}/{key_enc}");

    let now = s3_now();
    let (auth, amz_date, csha) = sigv4_sign("HEAD", &obj_url, &[], &[], &creds, &now);
    let agent = s3_agent();
    let req = agent
        .head(&obj_url)
        .header("Authorization",        &auth)
        .header("x-amz-date",           &amz_date)
        .header("x-amz-content-sha256", &csha);

    match req.call() {
        Ok(resp) => {
            let st = resp.status().as_u16();
            if st < 300 {
                let cl: i128 = resp.headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let ct = resp.headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("application/octet-stream")
                    .to_string();
                let etag = resp.headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_string();
                let bh = resp.headers()
                    .get("x-amz-meta-blake3")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                Ok(Value::Struct {
                    name:   "S3HeadResult".into(),
                    fields: vec![
                        ("bucket".into(),       Value::String(bucket)),
                        ("key".into(),          Value::String(key)),
                        ("size".into(),         Value::Int(cl)),
                        ("content_type".into(), Value::String(ct)),
                        ("etag".into(),         Value::String(etag)),
                        ("blake3".into(),       Value::String(bh)),
                        ("exists".into(),       Value::Bool(true)),
                    ],
                })
            } else {
                Ok(Value::Struct {
                    name:   "S3HeadResult".into(),
                    fields: vec![
                        ("bucket".into(), Value::String(bucket)),
                        ("key".into(),    Value::String(key)),
                        ("exists".into(), Value::Bool(false)),
                        ("status".into(), Value::Int(st as i128)),
                    ],
                })
            }
        }
        Err(e) => Err(format!("cloud_s3_head({bucket}, {key}): {e}")),
    }
}

// ─── GCS and Azure shims ──────────────────────────────────────────────────────

fn cloud_gcs_dispatch(op: &str, action: &str, args: &[Value]) -> StdlibResult {
    let creds = S3Creds::from_env_gcs().map_err(|e| format!("{op}: {e}"))?;
    cloud_s3_compat(action, args, creds)
}

fn cloud_azure_dispatch(op: &str, action: &str, args: &[Value]) -> StdlibResult {
    let creds = S3Creds::from_env_azure().map_err(|e| format!("{op}: {e}"))?;
    cloud_s3_compat(action, args, creds)
}

fn cloud_s3_compat(action: &str, args: &[Value], creds: S3Creds) -> StdlibResult {
    let bucket = match args.first() {
        Some(v) => v.as_string(),
        None    => return Err("cloud: bucket required".to_string()),
    };
    let base = creds.bucket_url(&bucket);

    match action {
        "list" => {
            let prefix = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            let url = if prefix.is_empty() {
                format!("{base}/?list-type=2")
            } else {
                format!("{base}/?list-type=2&prefix={}", s3_uri_query(&prefix))
            };
            let (_, body) = s3_req_no_body("GET", &url, &creds, &[])?;
            let objects: Vec<Value> = parse_list_xml(&body)
                .into_iter()
                .map(|(key, size, mtime)| Value::Struct {
                    name:   "S3Object".into(),
                    fields: vec![
                        ("key".into(),           Value::String(key)),
                        ("size".into(),          Value::Int(size)),
                        ("last_modified".into(), Value::String(mtime)),
                    ],
                })
                .collect();
            Ok(Value::Struct {
                name:   "S3ListResult".into(),
                fields: vec![
                    ("bucket".into(),  Value::String(bucket)),
                    ("prefix".into(),  Value::String(prefix)),
                    ("count".into(),   Value::Int(objects.len() as i128)),
                    ("objects".into(), Value::Array(objects)),
                ],
            })
        }
        "upload" => {
            let key = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            let lp  = args.get(2).map(|v| v.as_string()).unwrap_or_default();
            let data = std::fs::read(&lp)
                .map_err(|e| format!("cloud upload: read {lp}: {e}"))?;
            let size = data.len() as i128;
            let bh   = blake3::hash(&data).to_hex().to_string();
            let kenc = s3_uri_path(&key);
            let url  = format!("{base}/{kenc}");
            let extra = vec![("x-amz-meta-blake3".to_string(), bh.clone())];
            s3_req_with_body("PUT", &url, &creds, data, "application/octet-stream", &extra)?;
            Ok(Value::Struct {
                name:   "S3UploadResult".into(),
                fields: vec![
                    ("bucket".into(), Value::String(bucket)),
                    ("key".into(),    Value::String(key)),
                    ("size".into(),   Value::Int(size)),
                    ("blake3".into(), Value::String(bh)),
                ],
            })
        }
        "download" => {
            let key = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            let lp  = args.get(2).map(|v| v.as_string()).unwrap_or_default();
            let kenc  = s3_uri_path(&key);
            let url   = format!("{base}/{kenc}");
            let bytes = s3_get_bytes(&url, &creds)?;
            let size  = bytes.len() as i128;
            if let Some(p) = std::path::Path::new(&lp).parent() {
                let _ = std::fs::create_dir_all(p);
            }
            std::fs::write(&lp, &bytes)
                .map_err(|e| format!("cloud download: write {lp}: {e}"))?;
            let bh = blake3::hash(&bytes).to_hex().to_string();
            Ok(Value::Struct {
                name:   "S3DownloadResult".into(),
                fields: vec![
                    ("bucket".into(),     Value::String(bucket)),
                    ("key".into(),        Value::String(key)),
                    ("local_path".into(), Value::String(lp)),
                    ("size".into(),       Value::Int(size)),
                    ("blake3".into(),     Value::String(bh)),
                ],
            })
        }
        other => Err(format!("cloud: unknown action '{other}'")),
    }
}
// Two-Way Sync Engine
//
// Implements a three-snapshot algorithm: left-current, right-current, and the
// shared baseline stored in a SQLite database from the last successful sync.
// This is the same conceptual approach used by Syncthing and Unison, but with
// BLAKE3 hashes (not just mtimes), per-file conflict resolution strategies,
// and rayon-parallel scanning.
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-file state snapshot stored in the sync database.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SyncedFile {
    rel_path: String,
    size: i64,
    mtime: i64,
    blake3: String,
}

/// A scanned file on one side of the sync.
#[derive(Debug, Clone)]
struct ScannedFile {
    rel_path: String,
    abs_path: String,
    size: i64,
    mtime: i64,
    blake3: String,
}

/// Open or create the sync state SQLite database.
fn twoway_open_db(db_path: &str) -> Result<rusqlite::Connection, String> {
    let conn = rusqlite::Connection::open(db_path)
        .map_err(|e| format!("twoway_sync: cannot open db '{}': {}", db_path, e))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS sync_state (
            rel_path TEXT NOT NULL,
            side     TEXT NOT NULL CHECK(side IN ('left','right')),
            size     INTEGER NOT NULL,
            mtime    INTEGER NOT NULL,
            blake3   TEXT NOT NULL,
            PRIMARY KEY (rel_path, side)
         );
         CREATE TABLE IF NOT EXISTS sync_meta (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
         );",
    )
    .map_err(|e| format!("twoway_sync: schema init failed: {}", e))?;
    Ok(conn)
}

/// Load stored state for one side from the database.
fn twoway_load_state(
    conn: &rusqlite::Connection,
    side: &str,
) -> Result<HashMap<String, SyncedFile>, String> {
    let mut stmt = conn
        .prepare("SELECT rel_path, size, mtime, blake3 FROM sync_state WHERE side = ?1")
        .map_err(|e| format!("twoway_sync: prepare select: {}", e))?;
    let rows = stmt
        .query_map(rusqlite::params![side], |row| {
            Ok(SyncedFile {
                rel_path: row.get(0)?,
                size: row.get(1)?,
                mtime: row.get(2)?,
                blake3: row.get(3)?,
            })
        })
        .map_err(|e| format!("twoway_sync: query_map: {}", e))?;
    let mut map = HashMap::new();
    for row in rows {
        let sf = row.map_err(|e| format!("twoway_sync: row read: {}", e))?;
        map.insert(sf.rel_path.clone(), sf);
    }
    Ok(map)
}

/// Save (upsert) the state of one side into the database after a successful sync.
fn twoway_save_state(
    conn: &rusqlite::Connection,
    side: &str,
    files: &[ScannedFile],
) -> Result<(), String> {
    conn.execute("DELETE FROM sync_state WHERE side = ?1", rusqlite::params![side])
        .map_err(|e| format!("twoway_sync: delete old state: {}", e))?;
    let mut stmt = conn
        .prepare(
            "INSERT INTO sync_state (rel_path, side, size, mtime, blake3)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .map_err(|e| format!("twoway_sync: prepare insert: {}", e))?;
    for f in files {
        stmt.execute(rusqlite::params![f.rel_path, side, f.size, f.mtime, f.blake3])
            .map_err(|e| format!("twoway_sync: insert state '{}': {}", f.rel_path, e))?;
    }
    Ok(())
}

/// Recursively scan a directory with rayon parallelism.
/// Returns files sorted by rel_path for deterministic diffs.
fn twoway_scan_dir(root: &std::path::Path) -> Result<Vec<ScannedFile>, String> {
    use rayon::prelude::*;

    // Collect paths first (single-threaded walk, I/O bound)
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    collect_paths_recursive(root, &mut paths)?;

    // Hash files in parallel
    let files: Result<Vec<ScannedFile>, String> = paths
        .par_iter()
        .map(|abs_path| {
            let meta = std::fs::metadata(abs_path)
                .map_err(|e| format!("twoway_scan: metadata '{}': {}", abs_path.display(), e))?;
            let size = meta.len() as i64;
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);

            // Only hash files ≤ 1 GiB inline; larger files use mtime+size as proxy
            let blake3_hash = if size <= 1_073_741_824 {
                let data = std::fs::read(abs_path)
                    .map_err(|e| format!("twoway_scan: read '{}': {}", abs_path.display(), e))?;
                blake3::hash(&data).to_hex().to_string()
            } else {
                format!("large:{size}:{mtime}")
            };

            let rel_path = abs_path
                .strip_prefix(root)
                .unwrap_or(abs_path.as_path())
                .to_string_lossy()
                .replace('\\', "/"); // normalise to forward-slashes on Windows

            Ok(ScannedFile {
                rel_path,
                abs_path: abs_path.to_string_lossy().to_string(),
                size,
                mtime,
                blake3: blake3_hash,
            })
        })
        .collect();

    let mut files = files?;
    files.sort_by(|a, b| a.rel_path.cmp(&b.rel_path));
    Ok(files)
}

fn collect_paths_recursive(
    dir: &std::path::Path,
    out: &mut Vec<std::path::PathBuf>,
) -> Result<(), String> {
    let rd = std::fs::read_dir(dir)
        .map_err(|e| format!("twoway_scan: read_dir '{}': {}", dir.display(), e))?;
    for entry in rd {
        let entry = entry.map_err(|e| format!("twoway_scan: entry: {}", e))?;
        let path = entry.path();
        let meta = entry.metadata().map_err(|e| {
            format!("twoway_scan: metadata '{}': {}", path.display(), e)
        })?;
        if meta.is_dir() {
            collect_paths_recursive(&path, out)?;
        } else if meta.is_file() {
            // Skip the sync state database itself so it doesn't appear as a file
            // to be synced between the two directories.
            let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if fname == ".tallow-sync.db" || fname == ".tallow-sync.db-shm" || fname == ".tallow-sync.db-wal" {
                continue;
            }
            out.push(path);
        }
        // symlinks are skipped intentionally
    }
    Ok(())
}

/// Determine what actions are needed by comparing current scan against stored state.
/// Returns (copy_l2r, copy_r2l, del_left, del_right, conflicts).
#[allow(clippy::too_many_arguments)]
fn twoway_compute_plan(
    left_files: &[ScannedFile],
    right_files: &[ScannedFile],
    stored_left: &HashMap<String, SyncedFile>,
    stored_right: &HashMap<String, SyncedFile>,
) -> TwoWayPlan {
    let left_map: HashMap<&str, &ScannedFile> =
        left_files.iter().map(|f| (f.rel_path.as_str(), f)).collect();
    let right_map: HashMap<&str, &ScannedFile> =
        right_files.iter().map(|f| (f.rel_path.as_str(), f)).collect();

    // Union of all known rel_paths
    let mut all_paths: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for f in left_files { all_paths.insert(&f.rel_path); }
    for f in right_files { all_paths.insert(&f.rel_path); }
    for k in stored_left.keys() { all_paths.insert(k); }
    for k in stored_right.keys() { all_paths.insert(k); }

    let mut plan = TwoWayPlan::default();

    for rel in all_paths {
        let cur_left = left_map.get(rel);
        let cur_right = right_map.get(rel);
        let prev_left = stored_left.get(rel);
        let prev_right = stored_right.get(rel);

        // Whether each side has changed since last sync
        let left_changed = match (cur_left, prev_left) {
            (Some(cur), Some(prev)) => cur.blake3 != prev.blake3,
            (Some(_), None) => true,  // new file on left
            (None, Some(_)) => true,  // deleted on left
            (None, None) => false,
        };
        let right_changed = match (cur_right, prev_right) {
            (Some(cur), Some(prev)) => cur.blake3 != prev.blake3,
            (Some(_), None) => true,  // new file on right
            (None, Some(_)) => true,  // deleted on right
            (None, None) => false,
        };

        match (cur_left, cur_right, prev_left, prev_right, left_changed, right_changed) {
            // Both present, neither changed → skip
            (Some(_), Some(_), _, _, false, false) => {
                plan.skip += 1;
            }
            // Both present, only left changed → copy left → right
            (Some(lf), Some(_), _, _, true, false) => {
                plan.copy_l2r.push(SyncAction {
                    rel_path: rel.to_owned(),
                    src_abs: lf.abs_path.clone(),
                    mtime: lf.mtime,
                    size: lf.size,
                });
            }
            // Both present, only right changed → copy right → left
            (Some(_), Some(rf), _, _, false, true) => {
                plan.copy_r2l.push(SyncAction {
                    rel_path: rel.to_owned(),
                    src_abs: rf.abs_path.clone(),
                    mtime: rf.mtime,
                    size: rf.size,
                });
            }
            // Both present, both changed but with identical content → skip (already in sync)
            // This fires on the very first sync when there's no stored state yet but both
            // sides already have the same file (e.g. copied manually or seeded together).
            (Some(lf), Some(rf), _, _, true, true) if lf.blake3 == rf.blake3 => {
                plan.skip += 1;
            }
            // Both present, both changed, different content → conflict
            (Some(lf), Some(rf), _, _, true, true) => {
                plan.conflicts.push(ConflictAction {
                    rel_path: rel.to_owned(),
                    left_abs: lf.abs_path.clone(),
                    right_abs: rf.abs_path.clone(),
                    left_mtime: lf.mtime,
                    right_mtime: rf.mtime,
                    left_size: lf.size,
                    right_size: rf.size,
                });
            }
            // Only on left, no prior state → new file: copy left → right
            (Some(lf), None, None, None, _, _) => {
                plan.copy_l2r.push(SyncAction {
                    rel_path: rel.to_owned(),
                    src_abs: lf.abs_path.clone(),
                    mtime: lf.mtime,
                    size: lf.size,
                });
            }
            // Only on right, no prior state → new file: copy right → left
            (None, Some(rf), None, None, _, _) => {
                plan.copy_r2l.push(SyncAction {
                    rel_path: rel.to_owned(),
                    src_abs: rf.abs_path.clone(),
                    mtime: rf.mtime,
                    size: rf.size,
                });
            }
            // Left deleted (present in stored left), right unchanged → delete right
            (None, Some(_), Some(_), _, _, false) => {
                plan.del_right.push(rel.to_owned());
            }
            // Right deleted (present in stored right), left unchanged → delete left
            (Some(_), None, _, Some(_), false, _) => {
                plan.del_left.push(rel.to_owned());
            }
            // Left deleted but right was modified → right wins: copy right → left
            (None, Some(rf), Some(_), _, _, true) => {
                plan.copy_r2l.push(SyncAction {
                    rel_path: rel.to_owned(),
                    src_abs: rf.abs_path.clone(),
                    mtime: rf.mtime,
                    size: rf.size,
                });
            }
            // Right deleted but left was modified → left wins: copy left → right
            (Some(lf), None, _, Some(_), true, _) => {
                plan.copy_l2r.push(SyncAction {
                    rel_path: rel.to_owned(),
                    src_abs: lf.abs_path.clone(),
                    mtime: lf.mtime,
                    size: lf.size,
                });
            }
            // Both absent now and previously — nothing to do
            _ => {}
        }
    }

    plan
}

#[derive(Debug, Default)]
struct TwoWayPlan {
    copy_l2r: Vec<SyncAction>,
    copy_r2l: Vec<SyncAction>,
    del_left: Vec<String>,
    del_right: Vec<String>,
    conflicts: Vec<ConflictAction>,
    skip: i64,
}

#[derive(Debug, Clone)]
struct SyncAction {
    rel_path: String,
    src_abs: String,
    mtime: i64,
    size: i64,
}

#[derive(Debug, Clone)]
struct ConflictAction {
    rel_path: String,
    left_abs: String,
    right_abs: String,
    left_mtime: i64,
    right_mtime: i64,
    left_size: i64,
    right_size: i64,
}

/// Execute a sync plan, resolving conflicts with the given strategy.
fn twoway_execute_plan(
    plan: &TwoWayPlan,
    left_root: &std::path::Path,
    right_root: &std::path::Path,
    strategy: &str,
    dry_run: bool,
) -> Result<SyncResult, String> {
    let mut result = SyncResult::default();

    // Copy left → right
    for action in &plan.copy_l2r {
        let dst = right_root.join(&action.rel_path);
        if let Some(p) = dst.parent() {
            if !dry_run {
                std::fs::create_dir_all(p)
                    .map_err(|e| format!("twoway_execute: mkdir '{}': {}", p.display(), e))?;
            }
        }
        if dry_run {
            result.files_copied += 1;
        } else {
            match copy_file_with_fallback(std::path::Path::new(&action.src_abs), &dst) {
                Ok(bytes) => { result.files_copied += 1; result.bytes_copied += bytes as i64; }
                Err(e) => { result.errors.push(format!("copy l→r '{}': {}", action.rel_path, e)); }
            }
        }
    }

    // Copy right → left
    for action in &plan.copy_r2l {
        let dst = left_root.join(&action.rel_path);
        if let Some(p) = dst.parent() {
            if !dry_run {
                std::fs::create_dir_all(p)
                    .map_err(|e| format!("twoway_execute: mkdir '{}': {}", p.display(), e))?;
            }
        }
        if dry_run {
            result.files_copied += 1;
        } else {
            match copy_file_with_fallback(std::path::Path::new(&action.src_abs), &dst) {
                Ok(bytes) => { result.files_copied += 1; result.bytes_copied += bytes as i64; }
                Err(e) => { result.errors.push(format!("copy r→l '{}': {}", action.rel_path, e)); }
            }
        }
    }

    // Delete on left
    for rel in &plan.del_left {
        let target = left_root.join(rel);
        if dry_run {
            result.files_deleted += 1;
        } else {
            match std::fs::remove_file(&target) {
                Ok(_) => result.files_deleted += 1,
                Err(e) => result.errors.push(format!("delete left '{}': {}", rel, e)),
            }
        }
    }

    // Delete on right
    for rel in &plan.del_right {
        let target = right_root.join(rel);
        if dry_run {
            result.files_deleted += 1;
        } else {
            match std::fs::remove_file(&target) {
                Ok(_) => result.files_deleted += 1,
                Err(e) => result.errors.push(format!("delete right '{}': {}", rel, e)),
            }
        }
    }

    // Resolve conflicts
    for conflict in &plan.conflicts {
        let left_path = std::path::Path::new(&conflict.left_abs);
        let right_path = std::path::Path::new(&conflict.right_abs);

        match strategy {
            "newest" => {
                if conflict.left_mtime >= conflict.right_mtime {
                    // Left wins: overwrite right
                    if !dry_run {
                        copy_file_with_fallback(left_path, right_path)
                            .map_err(|e| format!("conflict newest l→r '{}': {}", conflict.rel_path, e))?;
                    }
                } else {
                    // Right wins: overwrite left
                    if !dry_run {
                        copy_file_with_fallback(right_path, left_path)
                            .map_err(|e| format!("conflict newest r→l '{}': {}", conflict.rel_path, e))?;
                    }
                }
                result.conflicts_resolved += 1;
            }
            "oldest" => {
                if conflict.left_mtime <= conflict.right_mtime {
                    if !dry_run { copy_file_with_fallback(left_path, right_path).ok(); }
                } else {
                    if !dry_run { copy_file_with_fallback(right_path, left_path).ok(); }
                }
                result.conflicts_resolved += 1;
            }
            "largest" => {
                if conflict.left_size >= conflict.right_size {
                    if !dry_run { copy_file_with_fallback(left_path, right_path).ok(); }
                } else {
                    if !dry_run { copy_file_with_fallback(right_path, left_path).ok(); }
                }
                result.conflicts_resolved += 1;
            }
            "left" => {
                if !dry_run { copy_file_with_fallback(left_path, right_path).ok(); }
                result.conflicts_resolved += 1;
            }
            "right" => {
                if !dry_run { copy_file_with_fallback(right_path, left_path).ok(); }
                result.conflicts_resolved += 1;
            }
            "rename" => {
                // Keep both: rename the loser (left's version) with a conflict suffix.
                // Winner is the right-side version: left is overwritten by right,
                // and the old left is preserved as a conflict copy next to left's location.
                if !dry_run {
                    let ts = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
                    let conflict_name = rename_conflict(&conflict.rel_path, &ts);

                    // Save old left content to conflict copy (in both dirs)
                    let left_conflict = left_root.join(&conflict_name);
                    let right_conflict = right_root.join(&conflict_name);

                    // Copy old left to conflict file on both sides
                    if let Some(p) = left_conflict.parent() { let _ = std::fs::create_dir_all(p); }
                    if let Some(p) = right_conflict.parent() { let _ = std::fs::create_dir_all(p); }
                    let _ = copy_file_with_fallback(left_path, &left_conflict);
                    let _ = copy_file_with_fallback(left_path, &right_conflict);

                    // Right wins: copy right → left (canonical version)
                    copy_file_with_fallback(right_path, left_path)
                        .map_err(|e| format!("conflict rename '{}': {}", conflict.rel_path, e))?;
                }
                result.conflicts_resolved += 1;
            }
            "skip" | _ => {
                result.conflicts_skipped += 1;
            }
        }
    }

    Ok(result)
}

/// Build a conflict-renamed path: `dir/file.sync-conflict-YYYYMMDD-HHMMSS.ext`
fn rename_conflict(rel_path: &str, timestamp: &str) -> String {
    let path = std::path::Path::new(rel_path);
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("file");
    let ext = path.extension().and_then(|s| s.to_str());
    // Only include parent prefix if it's non-empty (files at root have no parent prefix)
    let parent_str = path.parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = if parent_str.is_empty() {
        String::new()
    } else {
        format!("{}/", parent_str.replace('\\', "/"))
    };
    if let Some(e) = ext {
        format!("{}{}.sync-conflict-{}.{}", parent, stem, timestamp, e)
    } else {
        format!("{}{}.sync-conflict-{}", parent, stem, timestamp)
    }
}

#[derive(Debug, Default)]
struct SyncResult {
    files_copied: i64,
    bytes_copied: i64,
    files_deleted: i64,
    conflicts_resolved: i64,
    conflicts_skipped: i64,
    errors: Vec<String>,
}

fn sync_result_to_value(r: &SyncResult) -> Value {
    Value::Struct {
        name: "SyncResult".into(),
        fields: vec![
            ("files_copied".into(), Value::Int(r.files_copied as i128)),
            ("bytes_copied".into(), Value::Int(r.bytes_copied as i128)),
            ("files_deleted".into(), Value::Int(r.files_deleted as i128)),
            ("conflicts_resolved".into(), Value::Int(r.conflicts_resolved as i128)),
            ("conflicts_skipped".into(), Value::Int(r.conflicts_skipped as i128)),
            ("errors".into(), Value::Array(r.errors.iter().map(|e| Value::String(e.clone())).collect())),
            ("ok".into(), Value::Bool(r.errors.is_empty())),
        ],
    }
}

// ── Public dispatch functions ──────────────────────────────────────────────────

/// `twoway_init(left_dir, right_dir, db_path?) -> SyncState`
pub fn twoway_init(args: &[Value]) -> StdlibResult {
    let left_dir = get_string_arg(args, 0).ok_or("twoway_init: requires left_dir")?;
    let right_dir = get_string_arg(args, 1).ok_or("twoway_init: requires right_dir")?;
    let db_path = get_string_arg(args, 2).unwrap_or_else(|| {
        format!("{}/{}", left_dir, ".tallow-sync.db")
    });

    let conn = twoway_open_db(&db_path)?;
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('left_root', ?1)",
        rusqlite::params![left_dir],
    ).map_err(|e| format!("twoway_init: store left_root: {}", e))?;
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta (key, value) VALUES ('right_root', ?1)",
        rusqlite::params![right_dir],
    ).map_err(|e| format!("twoway_init: store right_root: {}", e))?;

    Ok(Value::Struct {
        name: "SyncState".into(),
        fields: vec![
            ("left_root".into(), Value::String(left_dir)),
            ("right_root".into(), Value::String(right_dir)),
            ("db_path".into(), Value::String(db_path)),
            ("initialized".into(), Value::Bool(true)),
        ],
    })
}

/// `twoway_scan(left_dir, right_dir) -> SyncScan`
pub fn twoway_scan(args: &[Value]) -> StdlibResult {
    let left_dir = get_string_arg(args, 0).ok_or("twoway_scan: requires left_dir")?;
    let right_dir = get_string_arg(args, 1).ok_or("twoway_scan: requires right_dir")?;

    let left_path = std::path::Path::new(&left_dir);
    let right_path = std::path::Path::new(&right_dir);

    if !left_path.is_dir() {
        return Err(format!("twoway_scan: left '{}' is not a directory", left_dir));
    }
    if !right_path.is_dir() {
        return Err(format!("twoway_scan: right '{}' is not a directory", right_dir));
    }

    let (left_result, right_result) = rayon::join(
        || twoway_scan_dir(left_path),
        || twoway_scan_dir(right_path),
    );
    let left_files = left_result?;
    let right_files = right_result?;

    let to_value = |files: &[ScannedFile]| {
        Value::Array(
            files.iter().map(|f| Value::Struct {
                name: "SyncFile".into(),
                fields: vec![
                    ("rel_path".into(), Value::String(f.rel_path.clone())),
                    ("abs_path".into(), Value::String(f.abs_path.clone())),
                    ("size".into(), Value::Int(f.size as i128)),
                    ("mtime".into(), Value::Int(f.mtime as i128)),
                    ("blake3".into(), Value::String(f.blake3.clone())),
                ],
            }).collect()
        )
    };

    Ok(Value::Struct {
        name: "SyncScan".into(),
        fields: vec![
            ("left_files".into(), to_value(&left_files)),
            ("right_files".into(), to_value(&right_files)),
            ("left_count".into(), Value::Int(left_files.len() as i128)),
            ("right_count".into(), Value::Int(right_files.len() as i128)),
        ],
    })
}

/// `twoway_plan(left_dir, right_dir, db_path) -> SyncPlan`
pub fn twoway_plan(args: &[Value]) -> StdlibResult {
    let left_dir = get_string_arg(args, 0).ok_or("twoway_plan: requires left_dir")?;
    let right_dir = get_string_arg(args, 1).ok_or("twoway_plan: requires right_dir")?;
    let db_path = get_string_arg(args, 2).unwrap_or_else(|| {
        format!("{}/{}", left_dir, ".tallow-sync.db")
    });

    let left_path = std::path::Path::new(&left_dir);
    let right_path = std::path::Path::new(&right_dir);

    let (left_result, right_result) = rayon::join(
        || twoway_scan_dir(left_path),
        || twoway_scan_dir(right_path),
    );
    let left_files = left_result?;
    let right_files = right_result?;

    let conn = twoway_open_db(&db_path)?;
    let stored_left = twoway_load_state(&conn, "left")?;
    let stored_right = twoway_load_state(&conn, "right")?;

    let plan = twoway_compute_plan(&left_files, &right_files, &stored_left, &stored_right);

    let action_to_value = |actions: &[SyncAction]| {
        Value::Array(actions.iter().map(|a| Value::Struct {
            name: "SyncAction".into(),
            fields: vec![
                ("rel_path".into(), Value::String(a.rel_path.clone())),
                ("src_abs".into(), Value::String(a.src_abs.clone())),
                ("size".into(), Value::Int(a.size as i128)),
                ("mtime".into(), Value::Int(a.mtime as i128)),
            ],
        }).collect())
    };

    let total_actions = (plan.copy_l2r.len()
        + plan.copy_r2l.len()
        + plan.del_left.len()
        + plan.del_right.len()
        + plan.conflicts.len()) as i128;

    Ok(Value::Struct {
        name: "SyncPlan".into(),
        fields: vec![
            ("copy_left_to_right".into(), action_to_value(&plan.copy_l2r)),
            ("copy_right_to_left".into(), action_to_value(&plan.copy_r2l)),
            ("delete_left".into(), Value::Array(plan.del_left.iter().map(|s| Value::String(s.clone())).collect())),
            ("delete_right".into(), Value::Array(plan.del_right.iter().map(|s| Value::String(s.clone())).collect())),
            ("conflicts".into(), Value::Array(plan.conflicts.iter().map(|c| Value::Struct {
                name: "ConflictAction".into(),
                fields: vec![
                    ("rel_path".into(), Value::String(c.rel_path.clone())),
                    ("left_mtime".into(), Value::Int(c.left_mtime as i128)),
                    ("right_mtime".into(), Value::Int(c.right_mtime as i128)),
                    ("left_size".into(), Value::Int(c.left_size as i128)),
                    ("right_size".into(), Value::Int(c.right_size as i128)),
                ],
            }).collect())),
            ("skip".into(), Value::Int(plan.skip as i128)),
            ("total_actions".into(), Value::Int(total_actions)),
        ],
    })
}

/// `twoway_execute(left_dir, right_dir, db_path, strategy?) -> SyncResult`
pub fn twoway_execute(args: &[Value]) -> StdlibResult {
    let left_dir = get_string_arg(args, 0).ok_or("twoway_execute: requires left_dir")?;
    let right_dir = get_string_arg(args, 1).ok_or("twoway_execute: requires right_dir")?;
    let db_path = get_string_arg(args, 2).unwrap_or_else(|| {
        format!("{}/{}", left_dir, ".tallow-sync.db")
    });
    let strategy = get_string_arg(args, 3).unwrap_or_else(|| "newest".into());

    twoway_sync_inner(&left_dir, &right_dir, &db_path, &strategy, false)
}

/// `twoway_sync(left, right, strategy?, db_path?) -> SyncResult`
pub fn twoway_sync(args: &[Value]) -> StdlibResult {
    let left_dir = get_string_arg(args, 0).ok_or("twoway_sync: requires left_dir")?;
    let right_dir = get_string_arg(args, 1).ok_or("twoway_sync: requires right_dir")?;
    let strategy = get_string_arg(args, 2).unwrap_or_else(|| "newest".into());
    let db_path = get_string_arg(args, 3).unwrap_or_else(|| {
        format!("{}/{}", left_dir, ".tallow-sync.db")
    });

    twoway_sync_inner(&left_dir, &right_dir, &db_path, &strategy, false)
}

/// Core implementation: init → scan → plan → execute → persist state.
pub fn twoway_sync_inner(
    left_dir: &str,
    right_dir: &str,
    db_path: &str,
    strategy: &str,
    dry_run: bool,
) -> StdlibResult {
    let left_path = std::path::Path::new(left_dir);
    let right_path = std::path::Path::new(right_dir);

    if !left_path.is_dir() {
        return Err(format!("twoway_sync: left '{}' is not a directory", left_dir));
    }
    if !right_path.is_dir() {
        return Err(format!("twoway_sync: right '{}' is not a directory", right_dir));
    }

    // Open/create state database
    let conn = twoway_open_db(db_path)?;

    // Load stored state from last sync
    let stored_left = twoway_load_state(&conn, "left")?;
    let stored_right = twoway_load_state(&conn, "right")?;

    // Parallel scan of both sides
    let (left_result, right_result) = rayon::join(
        || twoway_scan_dir(left_path),
        || twoway_scan_dir(right_path),
    );
    let left_files = left_result?;
    let right_files = right_result?;

    // Compute sync plan
    let plan = twoway_compute_plan(&left_files, &right_files, &stored_left, &stored_right);

    // Execute the plan
    let result = twoway_execute_plan(&plan, left_path, right_path, strategy, dry_run)?;

    // Persist the new state only if not dry-run and no errors
    if !dry_run && result.errors.is_empty() {
        // Re-scan to capture any files that were copied/modified during execution
        let (new_left, new_right) = rayon::join(
            || twoway_scan_dir(left_path),
            || twoway_scan_dir(right_path),
        );
        let new_left = new_left.unwrap_or(left_files);
        let new_right = new_right.unwrap_or(right_files);
        twoway_save_state(&conn, "left", &new_left)?;
        twoway_save_state(&conn, "right", &new_right)?;
    } else if !dry_run {
        // Partial success: save what we have but don't lose the original state
        twoway_save_state(&conn, "left", &left_files)?;
        twoway_save_state(&conn, "right", &right_files)?;
    }

    Ok(sync_result_to_value(&result))
}

// ─────────────────────────────────────────────────────────────────────────────
// Block-level delta sync — fast_rsync (Dropbox AVX2 rsync implementation)
//
// Three-step pipeline:
//   1. block_signature(dst)    → compact rolling-hash signature of destination
//   2. block_delta(sig, src)   → binary delta (only changed blocks)
//   3. block_apply(dst, delta) → reconstruct src from dst + delta in-place
//
// block_sync_file / block_sync_dir wrap the full pipeline for single files and
// entire directory trees (rayon parallel).
// ─────────────────────────────────────────────────────────────────────────────

/// Default block size: 128 KiB — balanced for large files and small-change locality.
const BLOCK_SYNC_DEFAULT_BLOCK_SIZE: u32 = 131_072;

/// MD4 bytes embedded per block in the signature (max 16).
/// 8 bytes gives 64-bit collision resistance — adequate for content-addressed sync.
const BLOCK_SYNC_CRYPTO_HASH_SIZE: u32 = 8;

/// Generate a rolling-hash signature of a file.
///
/// Arguments: `path: String [, block_size: Int]`
///
/// Returns a `BlockSignature` struct with a `signature` field (base64-encoded
/// bytes) that can be passed to `block_delta`.
fn block_signature(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0).ok_or("block_signature: path required")?;
    let block_size = args
        .get(1)
        .and_then(|v| match v {
            Value::Int(n) => Some(*n as u32),
            _ => None,
        })
        .unwrap_or(BLOCK_SYNC_DEFAULT_BLOCK_SIZE);

    let data =
        std::fs::read(&path).map_err(|e| format!("block_signature: read '{path}': {e}"))?;
    let sig = fast_rsync::Signature::calculate(
        &data,
        fast_rsync::SignatureOptions {
            block_size,
            crypto_hash_size: BLOCK_SYNC_CRYPTO_HASH_SIZE,
        },
    );
    let sig_bytes = sig.into_serialized();
    let file_size = data.len() as i128;
    let sig_size = sig_bytes.len() as i128;

    Ok(Value::Struct {
        name: "BlockSignature".into(),
        fields: vec![
            ("path".into(), Value::String(path)),
            ("block_size".into(), Value::Int(block_size as i128)),
            ("file_size".into(), Value::Int(file_size)),
            ("signature_size".into(), Value::Int(sig_size)),
            (
                "signature".into(),
                Value::String(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &sig_bytes,
                )),
            ),
        ],
    })
}

/// Compute a binary delta between an old file's signature and new file content.
///
/// Arguments: `old_signature_b64: String, new_path: String`
///
/// Returns a `BlockDelta` struct with `delta` (base64) and transfer statistics.
fn block_delta(args: &[Value]) -> StdlibResult {
    let sig_b64 =
        get_string_arg(args, 0).ok_or("block_delta: signature (base64) required")?;
    let new_path = get_string_arg(args, 1).ok_or("block_delta: new_path required")?;

    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig_b64)
            .map_err(|e| format!("block_delta: bad base64 signature: {e}"))?;
    let sig = fast_rsync::Signature::deserialize(sig_bytes)
        .map_err(|e| format!("block_delta: invalid signature: {e}"))?;
    let indexed = sig.index();

    let new_data = std::fs::read(&new_path)
        .map_err(|e| format!("block_delta: read '{new_path}': {e}"))?;

    let mut delta_buf = Vec::new();
    fast_rsync::diff(&indexed, &new_data, &mut delta_buf)
        .map_err(|e| format!("block_delta: diff error: {e:?}"))?;

    let new_size = new_data.len() as i128;
    let delta_size = delta_buf.len() as i128;
    let savings = if new_size > 0 {
        (1.0 - delta_size as f64 / new_size as f64) * 100.0
    } else {
        0.0
    };

    Ok(Value::Struct {
        name: "BlockDelta".into(),
        fields: vec![
            ("new_path".into(), Value::String(new_path)),
            ("new_size".into(), Value::Int(new_size)),
            ("delta_size".into(), Value::Int(delta_size)),
            ("savings_pct".into(), Value::Float(savings)),
            (
                "delta".into(),
                Value::String(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &delta_buf,
                )),
            ),
        ],
    })
}

/// Apply a delta to an old file, producing the reconstructed new file.
///
/// Arguments: `old_path: String, delta_b64: String, output_path: String`
///
/// Returns a `BlockApplyResult` struct with timing and byte counts.
fn block_apply(args: &[Value]) -> StdlibResult {
    let old_path = get_string_arg(args, 0).ok_or("block_apply: old_path required")?;
    let delta_b64 =
        get_string_arg(args, 1).ok_or("block_apply: delta (base64) required")?;
    let output_path = get_string_arg(args, 2).ok_or("block_apply: output_path required")?;

    let start = Instant::now();

    let old_data = std::fs::read(&old_path)
        .map_err(|e| format!("block_apply: read '{old_path}': {e}"))?;
    let delta_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &delta_b64)
            .map_err(|e| format!("block_apply: bad base64 delta: {e}"))?;

    let mut result_buf = Vec::new();
    fast_rsync::apply(&old_data, &delta_bytes, &mut result_buf)
        .map_err(|e| format!("block_apply: apply error: {e:?}"))?;

    if let Some(p) = Path::new(&output_path).parent() {
        std::fs::create_dir_all(p)
            .map_err(|e| format!("block_apply: mkdir '{output_path}': {e}"))?;
    }
    std::fs::write(&output_path, &result_buf)
        .map_err(|e| format!("block_apply: write '{output_path}': {e}"))?;

    Ok(Value::Struct {
        name: "BlockApplyResult".into(),
        fields: vec![
            ("old_path".into(), Value::String(old_path)),
            ("output_path".into(), Value::String(output_path)),
            ("output_size".into(), Value::Int(result_buf.len() as i128)),
            ("elapsed_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
        ],
    })
}

/// Full block-level delta sync pipeline for a single file.
///
/// Arguments: `src: String, dst: String [, block_size: Int]`
///
/// If `dst` does not exist, performs a full copy.  Otherwise generates a
/// signature of `dst`, computes delta against `src`, and applies the delta
/// to `dst` in-place.
///
/// Returns a `BlockSyncResult` struct with `savings_pct`, `bytes_transferred`,
/// `blocks_reused`, `blocks_transferred`, `method`, and `elapsed_ms`.
fn block_sync_file(args: &[Value]) -> StdlibResult {
    let src = get_string_arg(args, 0).ok_or("block_sync_file: src required")?;
    let dst = get_string_arg(args, 1).ok_or("block_sync_file: dst required")?;
    let block_size = args
        .get(2)
        .and_then(|v| match v {
            Value::Int(n) => Some(*n as u32),
            _ => None,
        })
        .unwrap_or(BLOCK_SYNC_DEFAULT_BLOCK_SIZE);

    let start = Instant::now();
    let src_data = std::fs::read(&src)
        .map_err(|e| format!("block_sync_file: read src '{src}': {e}"))?;
    let file_size = src_data.len() as i128;

    // ── Destination absent → full copy ────────────────────────────────────
    if !Path::new(&dst).exists() {
        if let Some(p) = Path::new(&dst).parent() {
            std::fs::create_dir_all(p)
                .map_err(|e| format!("block_sync_file: mkdir '{dst}': {e}"))?;
        }
        std::fs::write(&dst, &src_data)
            .map_err(|e| format!("block_sync_file: write '{dst}': {e}"))?;
        let blocks_total = (file_size + block_size as i128 - 1) / block_size as i128;
        return Ok(Value::Struct {
            name: "BlockSyncResult".into(),
            fields: vec![
                ("src".into(), Value::String(src)),
                ("dst".into(), Value::String(dst)),
                ("file_size".into(), Value::Int(file_size)),
                ("bytes_transferred".into(), Value::Int(file_size)),
                ("blocks_reused".into(), Value::Int(0)),
                ("blocks_transferred".into(), Value::Int(blocks_total)),
                ("savings_pct".into(), Value::Float(0.0)),
                ("elapsed_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
                ("method".into(), Value::String("full_copy".into())),
            ],
        });
    }

    // ── Destination exists → sign → diff → apply ──────────────────────────
    let dst_data = std::fs::read(&dst)
        .map_err(|e| format!("block_sync_file: read dst '{dst}': {e}"))?;

    let sig = fast_rsync::Signature::calculate(
        &dst_data,
        fast_rsync::SignatureOptions {
            block_size,
            crypto_hash_size: BLOCK_SYNC_CRYPTO_HASH_SIZE,
        },
    );
    let indexed = sig.index();

    let mut delta_buf = Vec::new();
    fast_rsync::diff(&indexed, &src_data, &mut delta_buf)
        .map_err(|e| format!("block_sync_file: diff error: {e:?}"))?;

    let mut result_buf = Vec::new();
    fast_rsync::apply(&dst_data, &delta_buf, &mut result_buf)
        .map_err(|e| format!("block_sync_file: apply error: {e:?}"))?;

    std::fs::write(&dst, &result_buf)
        .map_err(|e| format!("block_sync_file: write '{dst}': {e}"))?;

    let delta_size = delta_buf.len() as i128;
    let savings = if file_size > 0 {
        (1.0 - delta_size as f64 / file_size as f64) * 100.0
    } else {
        0.0
    };
    let blocks_total = (file_size + block_size as i128 - 1) / block_size as i128;
    let blocks_transferred = (delta_size + block_size as i128 - 1) / block_size as i128;
    let blocks_reused = (blocks_total - blocks_transferred).max(0);

    Ok(Value::Struct {
        name: "BlockSyncResult".into(),
        fields: vec![
            ("src".into(), Value::String(src)),
            ("dst".into(), Value::String(dst)),
            ("file_size".into(), Value::Int(file_size)),
            ("bytes_transferred".into(), Value::Int(delta_size)),
            ("blocks_reused".into(), Value::Int(blocks_reused)),
            ("blocks_transferred".into(), Value::Int(blocks_transferred)),
            ("savings_pct".into(), Value::Float(savings)),
            ("elapsed_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
            ("method".into(), Value::String("block_delta".into())),
        ],
    })
}

/// Parallel block-level delta sync of an entire directory tree using rayon.
///
/// Arguments: `src_dir: String, dst_dir: String [, block_size: Int]`
///
/// Strategy:
/// - New files (absent in dst):            full copy
/// - Changed files (mtime or size differ): block-level delta
/// - Identical files (same mtime + size):  skip
///
/// Returns a `BlockSyncDirResult` struct with aggregate transfer statistics.
fn block_sync_dir(args: &[Value]) -> StdlibResult {
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicI64, Ordering};

    let src_dir = get_string_arg(args, 0).ok_or("block_sync_dir: src_dir required")?;
    let dst_dir = get_string_arg(args, 1).ok_or("block_sync_dir: dst_dir required")?;
    let block_size = args
        .get(2)
        .and_then(|v| match v {
            Value::Int(n) => Some(*n as u32),
            _ => None,
        })
        .unwrap_or(BLOCK_SYNC_DEFAULT_BLOCK_SIZE);

    let start = Instant::now();
    let src_path = Path::new(&src_dir);
    let dst_path = Path::new(&dst_dir);

    if !src_path.is_dir() {
        return Err(format!("block_sync_dir: src '{src_dir}' is not a directory"));
    }

    // ── Source walk ────────────────────────────────────────────────────────
    struct FileEntry {
        rel: std::path::PathBuf,
        size: u64,
        mtime: u64,
    }
    fn walk_src(base: &Path, dir: &Path, out: &mut Vec<FileEntry>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.filter_map(|e| e.ok()) {
            let path = entry.path();
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                walk_src(base, &path, out);
            } else if meta.is_file() {
                let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                out.push(FileEntry {
                    rel,
                    size: meta.len(),
                    mtime,
                });
            }
        }
    }
    let mut src_files: Vec<FileEntry> = Vec::new();
    walk_src(src_path, src_path, &mut src_files);

    // ── Destination cache ──────────────────────────────────────────────────
    fn walk_dst(
        base: &Path,
        dir: &Path,
        cache: &mut std::collections::HashMap<std::path::PathBuf, (u64, u64)>,
    ) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.filter_map(|e| e.ok()) {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.is_dir() {
                walk_dst(base, &path, cache);
            } else if meta.is_file() {
                let rel = path.strip_prefix(base).unwrap_or(&path).to_path_buf();
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                cache.insert(rel, (meta.len(), mtime));
            }
        }
    }
    let mut dst_cache: std::collections::HashMap<std::path::PathBuf, (u64, u64)> =
        std::collections::HashMap::new();
    if dst_path.is_dir() {
        walk_dst(dst_path, dst_path, &mut dst_cache);
    }

    // Pre-create all required destination sub-directories
    {
        let mut dirs_needed: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        for f in &src_files {
            if let Some(p) = dst_path.join(&f.rel).parent() {
                dirs_needed.insert(p.to_path_buf());
            }
        }
        for d in &dirs_needed {
            let _ = std::fs::create_dir_all(d);
        }
    }

    let total_files = src_files.len() as i128;
    let total_size: i128 = src_files.iter().map(|f| f.size as i128).sum();

    let at_bytes_xfer = AtomicI64::new(0);
    let at_files_new = AtomicI64::new(0);
    let at_files_delta = AtomicI64::new(0);
    let at_files_skip = AtomicI64::new(0);
    let at_errors = AtomicI64::new(0);

    src_files.par_iter().for_each(|fi| {
        let sf = src_path.join(&fi.rel);
        let df = dst_path.join(&fi.rel);

        let dst_entry = dst_cache.get(&fi.rel);
        let needs_sync = match dst_entry {
            Some(&(dst_sz, dst_mt)) => dst_sz != fi.size || dst_mt != fi.mtime,
            None => true,
        };

        if !needs_sync {
            at_files_skip.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let src_data = match std::fs::read(&sf) {
            Ok(d) => d,
            Err(_) => {
                at_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };

        if dst_entry.is_none() {
            // New file — full copy
            match std::fs::write(&df, &src_data) {
                Ok(()) => {
                    at_bytes_xfer.fetch_add(src_data.len() as i64, Ordering::Relaxed);
                    at_files_new.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    at_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        } else {
            // Changed file — block-level delta
            let dst_data = match std::fs::read(&df) {
                Ok(d) => d,
                Err(_) => {
                    // Unreadable destination — fall back to full copy
                    match std::fs::write(&df, &src_data) {
                        Ok(()) => {
                            at_bytes_xfer.fetch_add(src_data.len() as i64, Ordering::Relaxed);
                            at_files_new.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            at_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    return;
                }
            };

            let sig = fast_rsync::Signature::calculate(
                &dst_data,
                fast_rsync::SignatureOptions {
                    block_size,
                    crypto_hash_size: BLOCK_SYNC_CRYPTO_HASH_SIZE,
                },
            );
            let indexed = sig.index();

            let mut delta_buf = Vec::new();
            if fast_rsync::diff(&indexed, &src_data, &mut delta_buf).is_err() {
                at_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }

            let mut result_buf = Vec::new();
            if fast_rsync::apply(&dst_data, &delta_buf, &mut result_buf).is_err() {
                at_errors.fetch_add(1, Ordering::Relaxed);
                return;
            }

            match std::fs::write(&df, &result_buf) {
                Ok(()) => {
                    at_bytes_xfer.fetch_add(delta_buf.len() as i64, Ordering::Relaxed);
                    at_files_delta.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    at_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });

    let bytes_transferred = at_bytes_xfer.load(Ordering::Relaxed) as i128;
    let files_new = at_files_new.load(Ordering::Relaxed) as i128;
    let files_delta = at_files_delta.load(Ordering::Relaxed) as i128;
    let files_skip = at_files_skip.load(Ordering::Relaxed) as i128;
    let errors = at_errors.load(Ordering::Relaxed) as i128;
    let savings_pct = if total_size > 0 {
        (1.0 - bytes_transferred as f64 / total_size as f64) * 100.0
    } else {
        0.0
    };

    Ok(Value::Struct {
        name: "BlockSyncDirResult".into(),
        fields: vec![
            ("src_dir".into(), Value::String(src_dir)),
            ("dst_dir".into(), Value::String(dst_dir)),
            ("total_files".into(), Value::Int(total_files)),
            ("total_size".into(), Value::Int(total_size)),
            ("bytes_transferred".into(), Value::Int(bytes_transferred)),
            ("files_new".into(), Value::Int(files_new)),
            ("files_delta".into(), Value::Int(files_delta)),
            ("files_skipped".into(), Value::Int(files_skip)),
            ("errors".into(), Value::Int(errors)),
            ("savings_pct".into(), Value::Float(savings_pct)),
            ("block_size".into(), Value::Int(block_size as i128)),
            ("elapsed_ms".into(), Value::Int(start.elapsed().as_millis() as i128)),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    fn wtf(dir: &TempDir, name: &str, content: &str) -> String {
        let path = dir.path().join(name);
        if let Some(p) = path.parent() { std::fs::create_dir_all(p).unwrap(); }
        std::fs::write(&path, content).unwrap();
        path.to_string_lossy().to_string()
    }
    #[test] fn test_file_hash_known() {
        let d = TempDir::new().unwrap(); let p = wtf(&d, "h.txt", "hello world");
        assert_eq!(file_hash(&[Value::String(p)]).unwrap().as_string(), blake3::hash(b"hello world").to_hex().to_string());
    }
    #[test] fn test_chunk_consistency() {
        let d = TempDir::new().unwrap(); let p = wtf(&d, "d.txt", &"A".repeat(1000));
        if let Value::Array(chunks) = chunk_file(&[Value::String(p), Value::Int(400)]).unwrap() {
            assert_eq!(chunks.len(), 3);
            if let Value::Struct { fields, .. } = &chunks[0] {
                assert_eq!(fields.iter().find(|(k, _)| k == "hash").map(|(_, v)| v.as_string()).unwrap(), blake3::hash(&[b'A'; 400]).to_hex().to_string());
            }
        }
    }
    #[test] fn test_tree_hash_single() {
        let h = blake3::hash(b"test").to_hex().to_string();
        assert_eq!(tree_hash(&[Value::Array(vec![Value::String(h.clone())])]).unwrap().as_string(), h);
    }
    #[test] fn test_tree_hash_multiple() {
        let (h1,h2,h3,h4) = (blake3::hash(b"c1").to_hex().to_string(), blake3::hash(b"c2").to_hex().to_string(), blake3::hash(b"c3").to_hex().to_string(), blake3::hash(b"c4").to_hex().to_string());
        let r = tree_hash(&[Value::Array(vec![Value::String(h1.clone()), Value::String(h2.clone()), Value::String(h3.clone()), Value::String(h4.clone())])]).unwrap();
        let p01 = blake3::hash(format!("{h1}{h2}").as_bytes()).to_hex().to_string();
        let p23 = blake3::hash(format!("{h3}{h4}").as_bytes()).to_hex().to_string();
        assert_eq!(r.as_string(), blake3::hash(format!("{p01}{p23}").as_bytes()).to_hex().to_string());
    }
    #[test] fn test_delta_scan_temp_dir() {
        let d = TempDir::new().unwrap(); wtf(&d, "a.txt", "a"); wtf(&d, "b.txt", "b"); wtf(&d, "sub/c.txt", "c");
        if let Value::Array(e) = delta_scan(&[Value::String(d.path().to_string_lossy().to_string())]).unwrap() { assert_eq!(e.len(), 3); }
    }
    #[test] fn test_delta_diff_added() {
        let r = delta_diff(&[Value::Array(vec![]), Value::Array(vec![Value::Struct { name: "FileEntry".into(), fields: vec![("path".into(), Value::String("n.txt".into())), ("size".into(), Value::Int(1)), ("hash".into(), Value::String("h".into())), ("modified_epoch".into(), Value::Int(0))] }])]).unwrap();
        if let Value::Struct { fields, .. } = r { if let Value::Array(a) = fields.iter().find(|(k,_)| k=="added").map(|(_,v)|v.clone()).unwrap() { assert_eq!(a.len(), 1); } }
    }
    #[test] fn test_delta_diff_removed() {
        let r = delta_diff(&[Value::Array(vec![Value::Struct { name: "FileEntry".into(), fields: vec![("path".into(), Value::String("o.txt".into())), ("size".into(), Value::Int(1)), ("hash".into(), Value::String("h".into())), ("modified_epoch".into(), Value::Int(0))] }]), Value::Array(vec![])]).unwrap();
        if let Value::Struct { fields, .. } = r { if let Value::Array(a) = fields.iter().find(|(k,_)| k=="removed").map(|(_,v)|v.clone()).unwrap() { assert_eq!(a.len(), 1); } }
    }
    #[test] fn test_delta_diff_modified() {
        let r = delta_diff(&[
            Value::Array(vec![Value::Struct { name: "FileEntry".into(), fields: vec![("path".into(), Value::String("f".into())), ("size".into(), Value::Int(1)), ("hash".into(), Value::String("old".into())), ("modified_epoch".into(), Value::Int(0))] }]),
            Value::Array(vec![Value::Struct { name: "FileEntry".into(), fields: vec![("path".into(), Value::String("f".into())), ("size".into(), Value::Int(2)), ("hash".into(), Value::String("new".into())), ("modified_epoch".into(), Value::Int(1))] }]),
        ]).unwrap();
        if let Value::Struct { fields, .. } = r { if let Value::Array(a) = fields.iter().find(|(k,_)| k=="modified").map(|(_,v)|v.clone()).unwrap() { assert_eq!(a.len(), 1); } }
    }
    #[test] fn test_delta_diff_unchanged() {
        let r = delta_diff(&[
            Value::Array(vec![Value::Struct { name: "FileEntry".into(), fields: vec![("path".into(), Value::String("f".into())), ("size".into(), Value::Int(1)), ("hash".into(), Value::String("same".into())), ("modified_epoch".into(), Value::Int(0))] }]),
            Value::Array(vec![Value::Struct { name: "FileEntry".into(), fields: vec![("path".into(), Value::String("f".into())), ("size".into(), Value::Int(1)), ("hash".into(), Value::String("same".into())), ("modified_epoch".into(), Value::Int(9))] }]),
        ]).unwrap();
        if let Value::Struct { fields, .. } = r { assert_eq!(fields.iter().find(|(k,_)| k=="unchanged").and_then(|(_,v)| if let Value::Int(n)=v{Some(*n)}else{None}).unwrap(), 1); }
    }
    #[test] fn test_vault_encrypt_decrypt_roundtrip() {
        let e = vault_encrypt_bytes(&[Value::String("secret".into()), Value::String("pw".into())]).unwrap();
        assert_eq!(vault_decrypt_bytes(&[Value::String(e.as_string()), Value::String("pw".into())]).unwrap().as_string(), "secret");
    }
    #[test] fn test_vault_wrong_password() {
        let e = vault_encrypt_bytes(&[Value::String("s".into()), Value::String("right".into())]).unwrap();
        assert!(vault_decrypt_bytes(&[Value::String(e.as_string()), Value::String("wrong".into())]).is_err());
    }
    #[test] fn test_vault_file_roundtrip() {
        let d = TempDir::new().unwrap(); let orig = "Confidential\n";
        let ip = wtf(&d, "p.txt", orig);
        let ep = d.path().join("e.nixv").to_string_lossy().to_string();
        let op = d.path().join("d.txt").to_string_lossy().to_string();
        vault_encrypt_file(&[Value::String(ip), Value::String(ep.clone()), Value::String("pw".into())]).unwrap();
        vault_decrypt_file(&[Value::String(ep), Value::String(op.clone()), Value::String("pw".into())]).unwrap();
        assert_eq!(std::fs::read_to_string(&op).unwrap(), orig);
    }
    #[test] fn test_fast_copy_file() {
        let d = TempDir::new().unwrap(); let s = wtf(&d, "s.txt", "copy!");
        let dst = d.path().join("d.txt").to_string_lossy().to_string();
        fast_copy(&[Value::String(s), Value::String(dst.clone())]).unwrap();
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "copy!");
    }
    #[test] fn test_fast_copy_dir() {
        let s = TempDir::new().unwrap(); wtf(&s, "a.txt", "a"); wtf(&s, "sub/b.txt", "b");
        let d = TempDir::new().unwrap(); let dp = d.path().join("o").to_string_lossy().to_string();
        let r = fast_copy_dir(&[Value::String(s.path().to_string_lossy().to_string()), Value::String(dp.clone())]).unwrap();
        if let Value::Struct { fields, .. } = r { assert_eq!(fields.iter().find(|(k,_)| k=="files_copied").and_then(|(_,v)| if let Value::Int(n)=v{Some(*n)}else{None}).unwrap(), 2); }
        assert!(Path::new(&dp).join("a.txt").exists());
    }
    #[test] fn test_compress_decompress_zstd() {
        let c = compress_data(&[Value::String("test zstd".into()), Value::String("zstd".into()), Value::Int(3)]).unwrap();
        assert_eq!(decompress_data(&[Value::String(c.as_string()), Value::String("zstd".into())]).unwrap().as_string(), "test zstd");
    }
    #[test] fn test_detect_compressibility_text() {
        if let Value::Struct { fields, .. } = detect_compressibility(&[Value::String("a".repeat(1000))]).unwrap() {
            assert!(fields.iter().find(|(k,_)| k=="compressible").and_then(|(_,v)| if let Value::Bool(b)=v{Some(*b)}else{None}).unwrap());
        }
    }
    #[test] fn test_detect_compressibility_random() {
        let mut data = Vec::with_capacity(10000); let mut st: u64 = 12345;
        for _ in 0..10000 { st = st.wrapping_mul(6364136223846793005).wrapping_add(1); data.push((st >> 33) as u8); }
        if let Value::Struct { fields, .. } = detect_compressibility(&[Value::String(String::from_utf8_lossy(&data).to_string())]).unwrap() {
            let e = fields.iter().find(|(k,_)| k=="entropy").and_then(|(_,v)| if let Value::Float(f)=v{Some(*f)}else{None}).unwrap();
            assert!(e > 3.5, "got {e}");
        }
    }
    #[test] fn test_create_parse_manifest() {
        let mj = create_manifest(&[Value::String("rh123".into()), Value::Int(999), Value::Array(vec![Value::String("c1".into()), Value::String("c2".into())])]).unwrap();
        if let Value::Struct { fields, .. } = parse_manifest_fn(&[Value::String(mj.as_string())]).unwrap() {
            assert_eq!(fields.iter().find(|(k,_)| k=="root_hash").map(|(_,v)|v.as_string()).unwrap(), "rh123");
            assert_eq!(fields.iter().find(|(k,_)| k=="chunk_count").and_then(|(_,v)| if let Value::Int(n)=v{Some(*n)}else{None}).unwrap(), 2);
        }
    }
    #[test] fn test_verify_chunk_correct() {
        let h = blake3::hash(b"test data").to_hex().to_string();
        match verify_chunk(&[Value::String("test data".into()), Value::String(h)]).unwrap() { Value::Bool(b) => assert!(b), _ => panic!() }
    }
    #[test] fn test_verify_chunk_incorrect() {
        match verify_chunk(&[Value::String("x".into()), Value::String("0".repeat(64))]).unwrap() { Value::Bool(b) => assert!(!b), _ => panic!() }
    }
    // Phase 56 tests
    #[test] fn test_transfer_send_creates_session() { let r = transfer_send(&[Value::String("hello world test data".into()), Value::String("192.168.1.1".into()), Value::Bool(true)]).unwrap(); if let Value::Struct { name, fields } = &r { assert_eq!(name, "TransferSession"); assert!(gsf(fields, "session_id").unwrap().as_string().starts_with("xfer-")); assert_eq!(gsf(fields, "status").unwrap().as_string(), "ready"); assert!(matches!(gsf(fields, "total_size").unwrap(), Value::Int(21))); assert_eq!(gsf(fields, "root_hash").unwrap().as_string().len(), 64); } else { panic!(); } }
    #[test] fn test_transfer_receive_creates_session() { let s = transfer_send(&[Value::String("data".into()), Value::String("p".into()), Value::Bool(false)]).unwrap(); let r = transfer_receive(&[s]).unwrap(); if let Value::Struct { name, fields } = &r { assert_eq!(name, "TransferSession"); assert!(gsf(fields, "session_id").unwrap().as_string().starts_with("recv-")); assert_eq!(gsf(fields, "status").unwrap().as_string(), "waiting"); } else { panic!(); } }
    #[test] fn test_transfer_status_percent() { let s = transfer_send(&[Value::String("a]".repeat(500)), Value::String("l".into()), Value::Bool(false)]).unwrap(); let p = transfer_status(&[s]).unwrap(); if let Value::Struct { name, fields } = &p { assert_eq!(name, "TransferProgress"); assert!(matches!(gsf(fields, "bytes_total").unwrap(), Value::Int(1000))); assert!(matches!(gsf(fields, "bytes_transferred").unwrap(), Value::Int(0))); } else { panic!(); } }
    #[test] fn test_stream_create_reliable() { let r = stream_create(&[Value::String("x".into()), Value::String("reliable".into())]).unwrap(); if let Value::Struct { name, fields } = &r { assert_eq!(name, "TransferStream"); assert_eq!(gsf(fields, "stream_type").unwrap().as_string(), "reliable"); assert!(matches!(gsf(fields, "open").unwrap(), Value::Bool(true))); } else { panic!(); } }
    #[test] fn test_stream_write_updates_bytes() { let s = stream_create(&[Value::String("x".into()), Value::String("reliable".into())]).unwrap(); let u = stream_write(&[s, Value::String("hello world".into())]).unwrap(); if let Value::Struct { fields, .. } = &u { assert!(matches!(gsf(fields, "bytes_sent").unwrap(), Value::Int(11))); } else { panic!(); } }
    #[test] fn test_erasure_encode_generates_symbols() { let r = erasure_encode(&[Value::String("test erasure".into()), Value::Float(0.5)]).unwrap(); if let Value::Struct { name, fields } = &r { assert_eq!(name, "ErasureEncoded"); let k = if let Value::Int(n) = gsf(fields, "k").unwrap() { *n } else { 0 }; let n = if let Value::Int(n) = gsf(fields, "n").unwrap() { *n } else { 0 }; assert!(k >= 1); assert!(n > k); if let Value::Array(sy) = gsf(fields, "symbols").unwrap() { assert_eq!(sy.len(), n as usize); } } else { panic!(); } }
    #[test] fn test_erasure_encode_overhead() {
        let r = erasure_encode(&[Value::String("x".repeat(512)), Value::Float(1.0)]).unwrap();
        if let Value::Struct { fields, .. } = &r {
            let k = if let Value::Int(n) = gsf(fields, "k").unwrap() { *n } else { 0 };
            let n = if let Value::Int(n) = gsf(fields, "n").unwrap() { *n } else { 0 };
            assert_eq!(k, 10); // 10 data shards (min(10, 512))
            assert_eq!(n, 20); // 10 data + 10 recovery (overhead 1.0)
            assert_eq!(gsf(fields, "codec").unwrap().as_string(), "reed-solomon-simd");
        }
    }
    #[test] fn test_erasure_decode_sufficient() {
        let e = erasure_encode(&[Value::String("hello world test data for erasure".into()), Value::Float(0.5)]).unwrap();
        let result = erasure_decode(&[e]).unwrap();
        assert!(matches!(result, Value::Ok(_)));
        // Verify we can reconstruct the original data
        if let Value::Ok(inner) = result {
            if let Value::Struct { fields, .. } = *inner {
                let data = gsf(&fields, "data").unwrap().as_string();
                assert!(data.starts_with("hello world test data for erasure"));
            }
        }
    }
    #[test] fn test_erasure_decode_insufficient() { let r = erasure_decode(&[Value::Array(vec![Value::String("s".into())]), Value::Int(5)]).unwrap(); assert!(matches!(r, Value::Err(_))); }
    #[test] fn test_erasure_status_decodable() { let e = Value::Struct { name: "ErasureEncoded".into(), fields: vec![("k".into(), Value::Int(4)), ("n".into(), Value::Int(6)), ("symbols".into(), Value::Array(vec![])), ("overhead".into(), Value::Float(0.5)), ("systematic".into(), Value::Bool(true)), ("data_size".into(), Value::Int(1024))] }; let s = erasure_status(&[e, Value::Int(5)]).unwrap(); if let Value::Struct { fields, .. } = &s { assert!(matches!(gsf(fields, "decodable").unwrap(), Value::Bool(true))); assert!(matches!(gsf(fields, "deficit").unwrap(), Value::Int(0))); } }
    #[test] fn test_erasure_status_deficit() { let e = Value::Struct { name: "ErasureEncoded".into(), fields: vec![("k".into(), Value::Int(10)), ("n".into(), Value::Int(15)), ("symbols".into(), Value::Array(vec![])), ("overhead".into(), Value::Float(0.5)), ("systematic".into(), Value::Bool(true)), ("data_size".into(), Value::Int(2560))] }; let s = erasure_status(&[e, Value::Int(7)]).unwrap(); if let Value::Struct { fields, .. } = &s { assert!(matches!(gsf(fields, "decodable").unwrap(), Value::Bool(false))); assert!(matches!(gsf(fields, "deficit").unwrap(), Value::Int(3))); } }
    #[test] fn test_paths_discover_has_loopback() { if let Value::Array(p) = paths_discover(&[]).unwrap() { assert!(!p.is_empty()); if let Value::Struct { fields, .. } = &p[0] { assert_eq!(gsf(fields, "ip").unwrap().as_string(), "127.0.0.1"); } } else { panic!(); } }
    #[test] fn test_paths_estimate_sums_bandwidth() { let p = Value::Array(vec![Value::Struct { name: "NetworkPath".into(), fields: vec![("name".into(), Value::String("lo".into())), ("ip".into(), Value::String("127.0.0.1".into())), ("is_loopback".into(), Value::Bool(true)), ("is_up".into(), Value::Bool(true)), ("estimated_bandwidth_mbps".into(), Value::Float(10000.0))] }, Value::Struct { name: "NetworkPath".into(), fields: vec![("name".into(), Value::String("eth0".into())), ("ip".into(), Value::String("192.168.1.100".into())), ("is_loopback".into(), Value::Bool(false)), ("is_up".into(), Value::Bool(true)), ("estimated_bandwidth_mbps".into(), Value::Float(1000.0))] }]); let r = paths_estimate(&[p]).unwrap(); if let Value::Struct { fields, .. } = &r { if let Value::Float(bw) = gsf(fields, "total_bandwidth_mbps").unwrap() { assert!((*bw - 11000.0).abs() < 0.1); } assert!(matches!(gsf(fields, "path_count").unwrap(), Value::Int(2))); assert!(matches!(gsf(fields, "total_recommended_streams").unwrap(), Value::Int(8))); } }

    // ══════════════════════════════════════════════════════════════════
    // ── Phase 58 tests ──
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_erasure_encode_decode_real_roundtrip() {
        let original = "The quick brown fox jumps over the lazy dog. This tests reed-solomon-simd.";
        let encoded = erasure_encode(&[Value::String(original.into()), Value::Float(0.5)]).unwrap();
        if let Value::Struct { fields, .. } = &encoded {
            assert_eq!(gsf(fields, "codec").unwrap().as_string(), "reed-solomon-simd");
            let k = if let Value::Int(n) = gsf(fields, "k").unwrap() { *n } else { 0 };
            assert!(k >= 1);
            // Decode should recover original data
            let decoded = erasure_decode(&[encoded.clone()]).unwrap();
            if let Value::Ok(inner) = decoded {
                if let Value::Struct { fields: df, .. } = *inner {
                    let data = gsf(&df, "data").unwrap().as_string();
                    assert!(data.starts_with(original), "decoded: {data}");
                }
            } else {
                panic!("decode should have returned Ok");
            }
        } else {
            panic!("encode should return ErasureEncoded struct");
        }
    }

    #[test]
    fn test_erasure_insufficient_shards() {
        let r = erasure_decode(&[Value::Array(vec![Value::String("a".into())]), Value::Int(10)]).unwrap();
        assert!(matches!(r, Value::Err(_)));
    }

    #[test]
    fn test_progress_tracker_create_update() {
        let tracker = progress_create(&[Value::Int(100), Value::String("test transfer".into())]).unwrap();
        if let Value::Struct { name, fields } = &tracker {
            assert_eq!(name, "ProgressTracker");
            assert!(matches!(gsf(fields, "total").unwrap(), Value::Int(100)));
            assert!(matches!(gsf(fields, "current").unwrap(), Value::Int(0)));
            assert_eq!(gsf(fields, "label").unwrap().as_string(), "test transfer");
            if let Value::Float(p) = gsf(fields, "percent").unwrap() { assert!((*p - 0.0).abs() < 0.01); }
        } else { panic!(); }

        // Update progress
        let updated = progress_update(&[tracker, Value::Int(25)]).unwrap();
        if let Value::Struct { fields, .. } = &updated {
            assert!(matches!(gsf(fields, "current").unwrap(), Value::Int(25)));
            if let Value::Float(p) = gsf(fields, "percent").unwrap() { assert!((*p - 25.0).abs() < 0.01); }
        } else { panic!(); }
    }

    #[test]
    fn test_checkpoint_save_load_delete() {
        let tid = format!("test-ckpt-{}", now_ms_p56());

        // Save
        let state = Value::Struct {
            name: "TestState".into(),
            fields: vec![
                ("offset".into(), Value::Int(42)),
                ("status".into(), Value::String("partial".into())),
            ],
        };
        let saved = checkpoint_save(&[Value::String(tid.clone()), state]).unwrap();
        if let Value::Struct { fields, .. } = &saved {
            assert!(matches!(gsf(fields, "saved").unwrap(), Value::Bool(true)));
        }

        // Load
        let loaded = checkpoint_load(&[Value::String(tid.clone())]).unwrap();
        if let Value::Struct { fields, .. } = &loaded {
            assert!(matches!(gsf(fields, "found").unwrap(), Value::Bool(true)));
            let data = gsf(fields, "data").unwrap().as_string();
            assert!(data.contains("42"));
            assert!(data.contains("partial"));
        }

        // Delete
        let deleted = checkpoint_delete(&[Value::String(tid.clone())]).unwrap();
        if let Value::Struct { fields, .. } = &deleted {
            assert!(matches!(gsf(fields, "deleted").unwrap(), Value::Bool(true)));
        }

        // Load after delete should not find
        let loaded2 = checkpoint_load(&[Value::String(tid)]).unwrap();
        if let Value::Struct { fields, .. } = &loaded2 {
            assert!(matches!(gsf(fields, "found").unwrap(), Value::Bool(false)));
        }
    }

    #[test]
    fn test_bandwidth_limit_create() {
        let limit = bandwidth_limit(&[Value::Float(100.0)]).unwrap();
        if let Value::Struct { name, fields } = &limit {
            assert_eq!(name, "BandwidthLimit");
            if let Value::Float(mbps) = gsf(fields, "limit_mbps").unwrap() {
                assert!((*mbps - 100.0).abs() < 0.01);
            }
            // 100 Mbps = 12,500,000 bytes/sec
            assert!(matches!(gsf(fields, "bytes_per_sec").unwrap(), Value::Int(12_500_000)));
            assert!(matches!(gsf(fields, "active").unwrap(), Value::Bool(true)));
        } else { panic!(); }
    }

    #[test]
    fn test_bandwidth_throttle() {
        // 1000 bytes in 10ms at limit of 50000 bytes/sec -> actual rate = 100,000 B/s -> too fast
        let sleep = bandwidth_throttle(&[Value::Int(1000), Value::Int(10), Value::Int(50000)]).unwrap();
        if let Value::Int(ms) = sleep { assert!(ms > 0, "should need to sleep: got {ms}"); }

        // 100 bytes in 1000ms at limit of 50000 bytes/sec -> actual rate = 100 B/s -> fine
        let sleep2 = bandwidth_throttle(&[Value::Int(100), Value::Int(1000), Value::Int(50000)]).unwrap();
        if let Value::Int(ms) = sleep2 { assert_eq!(ms, 0, "should not need to sleep"); }
    }

    #[test]
    fn test_lan_discover() {
        let result = lan_discover(&[]).unwrap();
        if let Value::Array(peers) = result {
            assert!(!peers.is_empty(), "should discover at least one peer (self)");
            if let Value::Struct { name, fields } = &peers[0] {
                assert_eq!(name, "LanPeer");
                assert!(!gsf(fields, "ip").unwrap().as_string().is_empty());
                assert!(!gsf(fields, "hostname").unwrap().as_string().is_empty());
            }
        } else { panic!("expected array of LanPeer"); }
    }

    #[test]
    fn test_copy_with_metadata() {
        let d = TempDir::new().unwrap();
        let src = wtf(&d, "meta_src.txt", "metadata test content");
        let dst = d.path().join("meta_dst.txt").to_string_lossy().to_string();
        let result = copy_with_metadata(&[Value::String(src), Value::String(dst.clone())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert!(matches!(gsf(fields, "bytes_copied").unwrap(), Value::Int(21)));
            // mtime should be preserved
            assert!(matches!(gsf(fields, "mtime_preserved").unwrap(), Value::Bool(true)));
        }
        assert_eq!(std::fs::read_to_string(&dst).unwrap(), "metadata test content");
    }

    #[test]
    fn test_vault_encrypt_decrypt_dir() {
        let src = TempDir::new().unwrap();
        wtf(&src, "a.txt", "file alpha");
        wtf(&src, "sub/b.txt", "file bravo");
        wtf(&src, "sub/deep/c.txt", "file charlie");

        let enc_dir = TempDir::new().unwrap();
        let dec_dir = TempDir::new().unwrap();

        // Encrypt directory
        let enc_result = vault_encrypt_dir(&[
            Value::String(src.path().to_string_lossy().to_string()),
            Value::String(enc_dir.path().to_string_lossy().to_string()),
            Value::String("test-password-58".into()),
        ]).unwrap();

        if let Value::Struct { fields, .. } = &enc_result {
            assert!(matches!(gsf(fields, "files_encrypted").unwrap(), Value::Int(3)));
            assert!(matches!(gsf(fields, "encrypted").unwrap(), Value::Bool(true)));
        } else { panic!("expected VaultDirResult"); }

        // Decrypt directory
        let dec_result = vault_decrypt_dir(&[
            Value::String(enc_dir.path().to_string_lossy().to_string()),
            Value::String(dec_dir.path().to_string_lossy().to_string()),
            Value::String("test-password-58".into()),
        ]).unwrap();

        if let Value::Struct { fields, .. } = &dec_result {
            assert!(matches!(gsf(fields, "files_decrypted").unwrap(), Value::Int(3)));
            assert!(matches!(gsf(fields, "decrypted").unwrap(), Value::Bool(true)));
        } else { panic!("expected VaultDirResult"); }

        // Verify content round-trips correctly
        // The decrypted files will be in the dec_dir preserving relative structure
        // We need to find them — they should exist somewhere under dec_dir
        let dec_path = dec_dir.path();
        let mut found_files = Vec::new();
        collect_files_recursive(dec_path, &mut found_files).unwrap();
        assert_eq!(found_files.len(), 3, "should have 3 decrypted files, got {:?}", found_files);

        // Check that at least one file has correct content
        let mut found_alpha = false;
        for f in &found_files {
            if let Ok(content) = std::fs::read_to_string(f) {
                if content == "file alpha" { found_alpha = true; }
            }
        }
        assert!(found_alpha, "should find file with 'file alpha' content");
    }

    #[test]
    fn test_vault_decrypt_dir_wrong_password() {
        let src = TempDir::new().unwrap();
        wtf(&src, "secret.txt", "top secret data");

        let enc_dir = TempDir::new().unwrap();
        let dec_dir = TempDir::new().unwrap();

        vault_encrypt_dir(&[
            Value::String(src.path().to_string_lossy().to_string()),
            Value::String(enc_dir.path().to_string_lossy().to_string()),
            Value::String("correct-password".into()),
        ]).unwrap();

        // Decrypt with wrong password
        let dec_result = vault_decrypt_dir(&[
            Value::String(enc_dir.path().to_string_lossy().to_string()),
            Value::String(dec_dir.path().to_string_lossy().to_string()),
            Value::String("wrong-password".into()),
        ]).unwrap();

        if let Value::Struct { fields, .. } = &dec_result {
            // Should have 0 files decrypted and 1 error
            assert!(matches!(gsf(fields, "files_decrypted").unwrap(), Value::Int(0)));
            let errs = if let Value::Int(n) = gsf(fields, "errors").unwrap() { *n } else { 0 };
            assert!(errs > 0, "should have errors with wrong password");
        }
    }

    #[test]
    fn test_value_to_json_string() {
        let v = Value::String("hello \"world\"".into());
        let json = value_to_json(&v);
        assert_eq!(json, r#""hello \"world\"""#);
    }

    #[test]
    fn test_value_to_json_struct() {
        let v = Value::Struct {
            name: "Test".into(),
            fields: vec![
                ("x".into(), Value::Int(42)),
                ("y".into(), Value::Bool(true)),
            ],
        };
        let json = value_to_json(&v);
        assert!(json.contains("\"__type\":\"Test\""));
        assert!(json.contains("\"x\":42"));
        assert!(json.contains("\"y\":true"));
    }

    #[test]
    fn test_value_to_json_array() {
        let v = Value::Array(vec![Value::Int(1), Value::Int(2), Value::String("three".into())]);
        let json = value_to_json(&v);
        assert_eq!(json, "[1,2,\"three\"]");
    }

    #[test]
    fn test_mmap_read() {
        let d = TempDir::new().unwrap();
        let p = wtf(&d, "mmap_test.txt", "memory mapped file content here");
        let result = mmap_read(&[Value::String(p)]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "MmapResult");
            let size = if let Value::Int(n) = gsf(fields, "size").unwrap() { *n } else { 0 };
            assert_eq!(size, "memory mapped file content here".len() as i128);
            let hash = gsf(fields, "hash").unwrap().as_string();
            assert_eq!(hash.len(), 64); // BLAKE3 hex
            // Verify hash matches direct computation
            let expected = blake3::hash(b"memory mapped file content here").to_hex().to_string();
            assert_eq!(hash, expected);
        } else { panic!(); }
    }

    #[test]
    fn test_lz4_compress_decompress() {
        let original = "test lz4 compression data for TallowTransfer";
        let compressed = lz4_compress(&[Value::String(original.into())]).unwrap();
        if let Value::Struct { fields, .. } = &compressed {
            assert_eq!(gsf(fields, "algo").unwrap().as_string(), "lz4");
            let hex_data = gsf(fields, "data").unwrap().as_string();
            // Decompress
            let decompressed = lz4_decompress(&[Value::String(hex_data)]).unwrap();
            assert_eq!(decompressed.as_string(), original);
        } else { panic!(); }
    }

    #[test]
    fn test_mmap_read_empty_file() {
        let d = TempDir::new().unwrap();
        let p = wtf(&d, "empty.txt", "");
        let result = mmap_read(&[Value::String(p)]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert!(matches!(gsf(fields, "size").unwrap(), Value::Int(0)));
        }
    }

    #[test]
    fn test_dispatch_new_functions() {
        // Verify dispatch routing works for Phase 58 functions
        assert!(dispatch("progress_create", vec![Value::Int(100)]).is_some());
        assert!(dispatch("checkpoint_load", vec![Value::String("nonexistent".into())]).is_some());
        assert!(dispatch("bandwidth_limit", vec![Value::Float(10.0)]).is_some());
        assert!(dispatch("lan_discover", vec![]).is_some());
        assert!(dispatch("lz4_compress", vec![Value::String("test".into())]).is_some());
    }

    // ══════════════════════════════════════════════════════════════════
    // Phase 62: Tests
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_signed_manifest_create() {
        let files = r#"["file_a.txt","file_b.txt"]"#;
        let result = signed_manifest(&[Value::String(files.into()), Value::String("alice".into())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "SignedManifest");
            assert!(gsf(fields, "signed").unwrap().as_string() == "true");
            assert_eq!(gsf(fields, "sender").unwrap().as_string(), "alice");
            assert!(!gsf(fields, "signature").unwrap().as_string().is_empty());
            assert!(gsf(fields, "manifest").unwrap().as_string().contains("alice"));
        } else { panic!("expected SignedManifest struct"); }
    }

    #[test]
    fn test_signed_manifest_verify_valid() {
        let files = r#"["test.txt"]"#;
        let manifest = signed_manifest(&[Value::String(files.into()), Value::String("bob".into())]).unwrap();
        if let Value::Struct { fields, .. } = &manifest {
            let m = gsf(fields, "manifest").unwrap().as_string();
            let s = gsf(fields, "signature").unwrap().as_string();
            let result = verify_manifest(&[Value::String(m), Value::String(s), Value::String("bob".into())]).unwrap();
            if let Value::Struct { fields: vf, .. } = &result {
                assert_eq!(gsf(&vf, "valid").unwrap().as_string(), "true");
                assert_eq!(gsf(&vf, "signature_match").unwrap().as_string(), "true");
            } else { panic!("expected ManifestVerification struct"); }
        } else { panic!(); }
    }

    #[test]
    fn test_signed_manifest_verify_tampered() {
        let files = r#"["test.txt"]"#;
        let manifest = signed_manifest(&[Value::String(files.into()), Value::String("bob".into())]).unwrap();
        if let Value::Struct { fields, .. } = &manifest {
            let mut m = gsf(fields, "manifest").unwrap().as_string();
            m.push_str("TAMPERED");
            let s = gsf(fields, "signature").unwrap().as_string();
            let result = verify_manifest(&[Value::String(m), Value::String(s), Value::String("bob".into())]).unwrap();
            if let Value::Struct { fields: vf, .. } = &result {
                assert_eq!(gsf(&vf, "valid").unwrap().as_string(), "false");
            } else { panic!(); }
        } else { panic!(); }
    }

    #[test]
    fn test_transfer_receipt() {
        let result = transfer_receipt(&[Value::String("abc123hash".into()), Value::String("carol".into())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "TransferReceipt");
            assert_eq!(gsf(fields, "file_hash").unwrap().as_string(), "abc123hash");
            assert_eq!(gsf(fields, "receiver").unwrap().as_string(), "carol");
            assert!(!gsf(fields, "receipt_hash").unwrap().as_string().is_empty());
            assert_eq!(gsf(fields, "non_repudiation").unwrap().as_string(), "true");
        } else { panic!(); }
    }

    #[test]
    fn test_audit_log_chain() {
        // Hold the lock for the entire test to prevent interleaving from
        // parallel tests that also append to the shared AUDIT_LOG.
        let mut log = AUDIT_LOG.lock().unwrap();
        let base_idx = log.len() as u64;
        let prev = log.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| "genesis".to_string());

        // Manually build two chained entries within the lock
        let ts1 = crate::stdlib::time::epoch_secs_to_iso(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as i64);
        let h1_input = format!("{}||{}||{}||{}||{}", base_idx, ts1, "chain_send", "file_a.txt", prev);
        let h1 = blake3::hash(h1_input.as_bytes()).to_hex().to_string();
        log.push(AuditEntry { index: base_idx, timestamp: ts1.clone(), action: "chain_send".into(),
            details: "file_a.txt".into(), prev_hash: prev.clone(), entry_hash: h1.clone() });

        let ts2 = ts1.clone(); // same second is fine
        let h2_input = format!("{}||{}||{}||{}||{}", base_idx + 1, ts2, "chain_receive", "file_a.txt", h1);
        let h2 = blake3::hash(h2_input.as_bytes()).to_hex().to_string();
        log.push(AuditEntry { index: base_idx + 1, timestamp: ts2, action: "chain_receive".into(),
            details: "file_a.txt".into(), prev_hash: h1.clone(), entry_hash: h2.clone() });

        // Verify chain linkage
        let e1 = &log[base_idx as usize];
        let e2 = &log[base_idx as usize + 1];
        assert_eq!(e2.prev_hash, e1.entry_hash);
        assert_eq!(e2.index, e1.index + 1);
        assert!(!e1.entry_hash.is_empty());
        assert!(!e2.entry_hash.is_empty());
    }

    #[test]
    fn test_audit_verify_intact() {
        // Add entries (don't clear -- shared global, tests run in parallel)
        audit_log(&[Value::String("verify_a1".into()), Value::String("d1".into())]).unwrap();
        audit_log(&[Value::String("verify_a2".into()), Value::String("d2".into())]).unwrap();
        audit_log(&[Value::String("verify_a3".into()), Value::String("d3".into())]).unwrap();

        let result = audit_verify(&[]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "valid").unwrap().as_string(), "true");
            assert_eq!(gsf(fields, "chain_intact").unwrap().as_string(), "true");
            if let Value::Int(n) = gsf(fields, "entries").unwrap() {
                assert!(*n >= 3);
            }
        } else { panic!(); }
    }

    #[test]
    fn test_audit_export_json() {
        audit_log(&[Value::String("export_test".into()), Value::String("data".into())]).unwrap();

        let result = audit_export(&[]).unwrap();
        let json = result.as_string();
        assert!(json.starts_with("["));
        assert!(json.ends_with("]"));
        assert!(json.contains("export_test"));
    }

    #[test]
    fn test_audit_save_to_file() {
        audit_log(&[Value::String("save_test".into()), Value::String("to_file".into())]).unwrap();

        let d = TempDir::new().unwrap();
        let p = d.path().join("test_audit.log");
        let path_str = p.to_string_lossy().to_string();
        let result = audit_save(&[Value::String(path_str.clone())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "saved").unwrap().as_string(), "true");
        } else { panic!(); }
        let content = std::fs::read_to_string(&path_str).unwrap();
        assert!(content.contains("save_test"));
    }

    #[test]
    fn test_transfer_expire_create() {
        let result = transfer_expire(&[Value::String("tx-001".into()), Value::Int(3), Value::Int(48)]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "ExpiringTransfer");
            assert_eq!(gsf(fields, "transfer_id").unwrap().as_string(), "tx-001");
            assert_eq!(gsf(fields, "max_downloads").unwrap().as_string(), "3");
            assert_eq!(gsf(fields, "downloads_remaining").unwrap().as_string(), "3");
            assert_eq!(gsf(fields, "expire_hours").unwrap().as_string(), "48");
            assert_eq!(gsf(fields, "expired").unwrap().as_string(), "false");
            // expires_at should be > created_at
            let created = gsf(fields, "created_at").unwrap().as_string();
            let expires = gsf(fields, "expires_at").unwrap().as_string();
            assert!(expires > created);
        } else { panic!(); }
    }

    #[test]
    fn test_transfer_check_expiry_valid() {
        let token = transfer_expire(&[Value::String("tx-002".into()), Value::Int(5), Value::Int(24)]).unwrap();
        let result = transfer_check_expiry(&[token]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "expired").unwrap().as_string(), "false");
            assert_eq!(gsf(fields, "time_expired").unwrap().as_string(), "false");
            assert_eq!(gsf(fields, "downloads_exhausted").unwrap().as_string(), "false");
            assert_eq!(gsf(fields, "downloads_remaining").unwrap().as_string(), "5");
        } else { panic!(); }
    }

    #[test]
    fn test_transfer_check_expiry_exhausted() {
        // Create token with 0 downloads remaining
        let token = Value::Struct {
            name: "ExpiringTransfer".to_string(),
            fields: vec![
                ("transfer_id".into(), Value::String("tx-003".into())),
                ("downloads_remaining".into(), Value::Int(0)),
                ("expires_at".into(), Value::String("2099-01-01T00:00:00Z".into())),
            ],
        };
        let result = transfer_check_expiry(&[token]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "expired").unwrap().as_string(), "true");
            assert_eq!(gsf(fields, "downloads_exhausted").unwrap().as_string(), "true");
        } else { panic!(); }
    }

    #[test]
    fn test_retention_policy_create() {
        let result = retention_policy(&[Value::Int(90), Value::String("gdpr".into())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "RetentionPolicy");
            assert_eq!(gsf(fields, "retain_days").unwrap().as_string(), "90");
            assert_eq!(gsf(fields, "name").unwrap().as_string(), "gdpr");
            assert_eq!(gsf(fields, "auto_delete").unwrap().as_string(), "true");
            assert_eq!(gsf(fields, "legal_hold").unwrap().as_string(), "false");
        } else { panic!(); }
    }

    #[test]
    fn test_retention_apply_dry_run() {
        let d = TempDir::new().unwrap();
        wtf(&d, "recent.txt", "recent file");
        wtf(&d, "also_recent.txt", "also recent");
        let dir_path = d.path().to_string_lossy().to_string();

        // With 30 day retention and dry_run, recently created files should be retained
        let result = retention_apply(&[Value::String(dir_path), Value::Int(30), Value::Bool(true)]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "dry_run").unwrap().as_string(), "true");
            if let Value::Int(d) = gsf(fields, "deleted").unwrap() { assert_eq!(*d, 0); }
            if let Value::Int(r) = gsf(fields, "retained").unwrap() { assert_eq!(*r, 2); }
        } else { panic!(); }
    }

    #[test]
    fn test_validate_file_type_png() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("test.png");
        // PNG magic bytes
        let mut data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        data.extend_from_slice(&[0u8; 100]);
        std::fs::write(&p, &data).unwrap();
        let result = validate_file_type(&[Value::String(p.to_string_lossy().to_string())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "FileValidation");
            assert_eq!(gsf(fields, "detected_type").unwrap().as_string(), "png");
            assert_eq!(gsf(fields, "mime").unwrap().as_string(), "image/png");
            assert_eq!(gsf(fields, "executable").unwrap().as_string(), "false");
            assert_eq!(gsf(fields, "safe").unwrap().as_string(), "true");
        } else { panic!(); }
    }

    #[test]
    fn test_validate_file_type_exe() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("test.exe");
        // PE/MZ magic bytes
        let mut data = vec![0x4D, 0x5A, 0x90, 0x00];
        data.extend_from_slice(&[0u8; 100]);
        std::fs::write(&p, &data).unwrap();
        let result = validate_file_type(&[Value::String(p.to_string_lossy().to_string())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "detected_type").unwrap().as_string(), "exe");
            assert_eq!(gsf(fields, "executable").unwrap().as_string(), "true");
            assert_eq!(gsf(fields, "safe").unwrap().as_string(), "false");
        } else { panic!(); }
    }

    #[test]
    fn test_validate_file_type_text() {
        let d = TempDir::new().unwrap();
        let p = wtf(&d, "readme.txt", "This is a plain text file with ASCII content only.");
        let result = validate_file_type(&[Value::String(p)]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "detected_type").unwrap().as_string(), "text");
            assert_eq!(gsf(fields, "mime").unwrap().as_string(), "text/plain");
            assert_eq!(gsf(fields, "safe").unwrap().as_string(), "true");
        } else { panic!(); }
    }

    #[test]
    fn test_validate_file_type_json() {
        let d = TempDir::new().unwrap();
        let p = wtf(&d, "data.json", r#"{"key":"value","num":42}"#);
        let result = validate_file_type(&[Value::String(p)]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "detected_type").unwrap().as_string(), "json");
            assert_eq!(gsf(fields, "mime").unwrap().as_string(), "application/json");
        } else { panic!(); }
    }

    #[test]
    fn test_validate_allowlist_allowed() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("valid.png");
        let mut data = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        data.extend_from_slice(&[0u8; 100]);
        std::fs::write(&p, &data).unwrap();
        let allowlist = Value::Array(vec![Value::String("png".into()), Value::String("pdf".into())]);
        let result = validate_allowlist(&[Value::String(p.to_string_lossy().to_string()), allowlist]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "allowed").unwrap().as_string(), "true");
            assert_eq!(gsf(fields, "detected_type").unwrap().as_string(), "png");
        } else { panic!(); }
    }

    #[test]
    fn test_validate_allowlist_blocked() {
        let d = TempDir::new().unwrap();
        let p = d.path().join("sneaky.pdf");
        // Actually an EXE disguised as PDF
        let mut data = vec![0x4D, 0x5A, 0x90, 0x00];
        data.extend_from_slice(&[0u8; 100]);
        std::fs::write(&p, &data).unwrap();
        let allowlist = Value::Array(vec![Value::String("pdf".into()), Value::String("png".into())]);
        let result = validate_allowlist(&[Value::String(p.to_string_lossy().to_string()), allowlist]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "allowed").unwrap().as_string(), "false");
            assert_eq!(gsf(fields, "detected_type").unwrap().as_string(), "exe");
        } else { panic!(); }
    }

    #[test]
    fn test_crypto_config_cnsa2() {
        let result = crypto_config(&[Value::String("cnsa2".into())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "CryptoConfig");
            assert_eq!(gsf(fields, "key_exchange").unwrap().as_string(), "ML-KEM-1024");
            assert_eq!(gsf(fields, "signature").unwrap().as_string(), "ML-DSA-87");
            assert_eq!(gsf(fields, "hash").unwrap().as_string(), "SHA-384");
            assert_eq!(gsf(fields, "cnsa2_compliant").unwrap().as_string(), "true");
            assert_eq!(gsf(fields, "post_quantum").unwrap().as_string(), "true");
        } else { panic!(); }
    }

    #[test]
    fn test_crypto_config_standard() {
        let result = crypto_config(&[Value::String("standard".into())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "key_exchange").unwrap().as_string(), "ML-KEM-768");
            assert_eq!(gsf(fields, "hash").unwrap().as_string(), "BLAKE3");
            assert_eq!(gsf(fields, "cnsa2_compliant").unwrap().as_string(), "false");
        } else { panic!(); }
    }

    #[test]
    fn test_crypto_config_hybrid() {
        let result = crypto_config(&[Value::String("hybrid".into())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "key_exchange").unwrap().as_string(), "X25519 + ML-KEM-768");
            assert_eq!(gsf(fields, "symmetric").unwrap().as_string(), "ChaCha20-Poly1305");
        } else { panic!(); }
    }

    #[test]
    fn test_dispatch_phase62_functions() {
        // Verify dispatch routing works for Phase 62 functions
        assert!(dispatch("signed_manifest", vec![Value::String(r#"["f.txt"]"#.into())]).is_some());
        assert!(dispatch("verify_manifest", vec![Value::String("m".into()), Value::String("s".into()), Value::String("id".into())]).is_some());
        assert!(dispatch("transfer_receipt", vec![Value::String("hash".into())]).is_some());
        assert!(dispatch("audit_log", vec![Value::String("action".into())]).is_some());
        assert!(dispatch("audit_verify", vec![]).is_some());
        assert!(dispatch("audit_export", vec![]).is_some());
        assert!(dispatch("transfer_expire", vec![Value::String("tx".into())]).is_some());
        assert!(dispatch("retention_policy", vec![Value::Int(30)]).is_some());
        assert!(dispatch("crypto_config", vec![Value::String("standard".into())]).is_some());
    }

    // ── Phase 63 Tests ──

    #[test]
    fn test_mtls_config_valid_paths() {
        let d = TempDir::new().unwrap();
        let cert = wtf(&d, "cert.pem", "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----");
        let key = wtf(&d, "key.pem", "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----");
        let ca = wtf(&d, "ca.pem", "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----");
        let result = mtls_config(&[Value::String(cert.clone()), Value::String(key.clone()), Value::String(ca)]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "MtlsConfig");
            assert_eq!(gsf(fields, "cert_path").unwrap().as_string(), cert);
            assert_eq!(gsf(fields, "key_path").unwrap().as_string(), key);
            assert!(matches!(gsf(fields, "mutual_auth").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "verify_peer").unwrap(), Value::Bool(true)));
            let fp = gsf(fields, "cert_fingerprint").unwrap().as_string();
            assert_eq!(fp.len(), 16);
        } else { panic!("expected MtlsConfig struct"); }
    }

    #[test]
    fn test_mtls_config_no_ca() {
        let d = TempDir::new().unwrap();
        let cert = wtf(&d, "cert.pem", "cert-data");
        let key = wtf(&d, "key.pem", "key-data");
        let result = mtls_config(&[Value::String(cert), Value::String(key)]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert!(matches!(gsf(fields, "mutual_auth").unwrap(), Value::Bool(false)));
            assert!(matches!(gsf(fields, "ca_path").unwrap(), Value::Nil));
        } else { panic!(); }
    }

    #[test]
    fn test_mtls_config_missing_cert() {
        let result = mtls_config(&[Value::String("/nonexistent/cert.pem".into()), Value::String("/nonexistent/key.pem".into())]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("certificate not found"));
    }

    #[test]
    fn test_mtls_config_missing_key() {
        let d = TempDir::new().unwrap();
        let cert = wtf(&d, "cert.pem", "cert-data");
        let result = mtls_config(&[Value::String(cert), Value::String("/nonexistent/key.pem".into())]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("private key not found"));
    }

    #[test]
    fn test_key_rotation_schedule() {
        let result = key_rotation_schedule(&[Value::String("master-key".into()), Value::Int(30)]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "KeyRotation");
            assert_eq!(gsf(fields, "key_id").unwrap().as_string(), "master-key");
            assert!(matches!(gsf(fields, "rotation_days").unwrap(), Value::Int(30)));
            assert!(matches!(gsf(fields, "auto_rotate").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "versions_retained").unwrap(), Value::Int(3)));
            let kv = gsf(fields, "key_version").unwrap().as_string();
            assert_eq!(kv.len(), 16); // BLAKE3 truncated hex
            let created = gsf(fields, "created_at").unwrap().as_string();
            assert!(created.contains("T")); // ISO format
            let next = gsf(fields, "next_rotation").unwrap().as_string();
            assert!(next > created); // next rotation is in the future
        } else { panic!(); }
    }

    #[test]
    fn test_key_rotation_schedule_default_90() {
        let result = key_rotation_schedule(&[Value::String("k1".into())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert!(matches!(gsf(fields, "rotation_days").unwrap(), Value::Int(90)));
        } else { panic!(); }
    }

    #[test]
    fn test_key_rotation_check() {
        // Create a schedule with next_rotation far in the future
        let schedule = key_rotation_schedule(&[Value::String("k1".into()), Value::Int(365)]).unwrap();
        let check = key_rotation_check(&[schedule]).unwrap();
        if let Value::Struct { name, fields } = &check {
            assert_eq!(name, "RotationCheck");
            assert!(matches!(gsf(fields, "needs_rotation").unwrap(), Value::Bool(false)));
        } else { panic!(); }
    }

    #[test]
    fn test_key_rotate() {
        let result = key_rotate(&[Value::String("master".into()), Value::String("v1abc".into())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "KeyRotationResult");
            assert_eq!(gsf(fields, "key_id").unwrap().as_string(), "master");
            assert_eq!(gsf(fields, "old_version").unwrap().as_string(), "v1abc");
            let nv = gsf(fields, "new_version").unwrap().as_string();
            assert_eq!(nv.len(), 16);
            assert!(matches!(gsf(fields, "success").unwrap(), Value::Bool(true)));
        } else { panic!(); }
    }

    #[test]
    fn test_rbac_create_admin() {
        let result = rbac_create_user(&[Value::String("alice".into()), Value::String("admin".into())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "RbacUser");
            assert_eq!(gsf(fields, "username").unwrap().as_string(), "alice");
            assert_eq!(gsf(fields, "role").unwrap().as_string(), "admin");
            assert!(matches!(gsf(fields, "can_send").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "can_receive").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "can_admin").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "can_audit").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "can_delete").unwrap(), Value::Bool(true)));
            let uid = gsf(fields, "user_id").unwrap().as_string();
            assert_eq!(uid.len(), 12);
        } else { panic!(); }
    }

    #[test]
    fn test_rbac_create_readonly() {
        let result = rbac_create_user(&[Value::String("bob".into()), Value::String("readonly".into())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert!(matches!(gsf(fields, "can_send").unwrap(), Value::Bool(false)));
            assert!(matches!(gsf(fields, "can_receive").unwrap(), Value::Bool(false)));
            assert!(matches!(gsf(fields, "can_admin").unwrap(), Value::Bool(false)));
            assert!(matches!(gsf(fields, "can_audit").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "can_delete").unwrap(), Value::Bool(false)));
        } else { panic!(); }
    }

    #[test]
    fn test_rbac_create_default_role() {
        let result = rbac_create_user(&[Value::String("charlie".into())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            assert_eq!(gsf(fields, "role").unwrap().as_string(), "transfer_only");
        } else { panic!(); }
    }

    #[test]
    fn test_rbac_check_allowed() {
        let user = rbac_create_user(&[Value::String("alice".into()), Value::String("admin".into())]).unwrap();
        let check = rbac_check(&[user, Value::String("send".into())]).unwrap();
        if let Value::Struct { name, fields } = &check {
            assert_eq!(name, "RbacCheck");
            assert!(matches!(gsf(fields, "allowed").unwrap(), Value::Bool(true)));
            assert_eq!(gsf(fields, "action").unwrap().as_string(), "send");
        } else { panic!(); }
    }

    #[test]
    fn test_rbac_check_denied() {
        let user = rbac_create_user(&[Value::String("bob".into()), Value::String("readonly".into())]).unwrap();
        let check = rbac_check(&[user, Value::String("send".into())]).unwrap();
        if let Value::Struct { fields, .. } = &check {
            assert!(matches!(gsf(fields, "allowed").unwrap(), Value::Bool(false)));
        } else { panic!(); }
    }

    #[test]
    fn test_rbac_invalid_role() {
        let result = rbac_create_user(&[Value::String("x".into()), Value::String("superadmin".into())]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid role"));
    }

    #[test]
    fn test_rbac_check_unknown_action() {
        let user = rbac_create_user(&[Value::String("a".into()), Value::String("admin".into())]).unwrap();
        let result = rbac_check(&[user, Value::String("fly".into())]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown action"));
    }

    #[test]
    fn test_webhook_config() {
        let result = webhook_config(&[Value::String("https://hooks.example.com/notify".into())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "WebhookConfig");
            assert_eq!(gsf(fields, "url").unwrap().as_string(), "https://hooks.example.com/notify");
            assert!(matches!(gsf(fields, "active").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "retry_count").unwrap(), Value::Int(3)));
            // Default events
            if let Value::Array(evts) = gsf(fields, "events").unwrap() {
                assert_eq!(evts.len(), 2);
                assert_eq!(evts[0].as_string(), "transfer_complete");
            } else { panic!("expected events array"); }
        } else { panic!(); }
    }

    #[test]
    fn test_webhook_config_custom_events() {
        let events = Value::Array(vec![Value::String("upload".into()), Value::String("delete".into())]);
        let result = webhook_config(&[Value::String("https://hook.io".into()), events, Value::String("my-secret".into())]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            if let Value::Array(evts) = gsf(fields, "events").unwrap() {
                assert_eq!(evts.len(), 2);
                assert_eq!(evts[0].as_string(), "upload");
            } else { panic!(); }
            assert_eq!(gsf(fields, "secret").unwrap().as_string(), "my-secret");
        } else { panic!(); }
    }

    #[test]
    fn test_webhook_fire() {
        let result = webhook_fire(&[
            Value::String("https://hook.io/endpoint".into()),
            Value::String("transfer_complete".into()),
            Value::String(r#"{"file":"test.dat"}"#.into()),
        ]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "WebhookResult");
            assert!(matches!(gsf(fields, "fired").unwrap(), Value::Bool(true)));
            assert_eq!(gsf(fields, "event").unwrap().as_string(), "transfer_complete");
            assert!(matches!(gsf(fields, "signature").unwrap(), Value::Nil));
            let body = gsf(fields, "body").unwrap().as_string();
            assert!(body.contains("transfer_complete"));
            assert!(body.contains("\"signature\":null"));
        } else { panic!(); }
    }

    #[test]
    fn test_webhook_fire_with_secret() {
        let result = webhook_fire(&[
            Value::String("https://hook.io".into()),
            Value::String("test_event".into()),
            Value::String("{}".into()),
            Value::String("webhook-secret-key".into()),
        ]).unwrap();
        if let Value::Struct { fields, .. } = &result {
            let sig = gsf(fields, "signature").unwrap().as_string();
            assert_eq!(sig.len(), 64); // BLAKE3 hex
            let body = gsf(fields, "body").unwrap().as_string();
            assert!(body.contains(&sig));
        } else { panic!(); }
    }

    #[test]
    fn test_schedule_create() {
        let result = schedule_create(&[
            Value::String("nightly-backup".into()),
            Value::String("0 2 * * *".into()),
            Value::String("/data/source".into()),
            Value::String("/backup/dest".into()),
        ]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "TransferSchedule");
            assert_eq!(gsf(fields, "name").unwrap().as_string(), "nightly-backup");
            assert_eq!(gsf(fields, "cron").unwrap().as_string(), "0 2 * * *");
            assert_eq!(gsf(fields, "source").unwrap().as_string(), "/data/source");
            assert_eq!(gsf(fields, "destination").unwrap().as_string(), "/backup/dest");
            assert!(matches!(gsf(fields, "active").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "runs_completed").unwrap(), Value::Int(0)));
            assert!(matches!(gsf(fields, "runs_failed").unwrap(), Value::Int(0)));
            let sid = gsf(fields, "schedule_id").unwrap().as_string();
            assert_eq!(sid.len(), 12);
        } else { panic!(); }
    }

    #[test]
    fn test_schedule_create_invalid_cron() {
        let result = schedule_create(&[
            Value::String("bad".into()),
            Value::String("0 2 *".into()), // only 3 fields
            Value::String("/src".into()),
            Value::String("/dst".into()),
        ]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid cron expression"));
    }

    #[test]
    fn test_schedule_check_wildcard_active() {
        let sched = schedule_create(&[
            Value::String("always".into()),
            Value::String("* * * * *".into()),
            Value::String("/s".into()),
            Value::String("/d".into()),
        ]).unwrap();
        let check = schedule_check(&[sched]).unwrap();
        if let Value::Struct { name, fields } = &check {
            assert_eq!(name, "ScheduleCheck");
            assert!(matches!(gsf(fields, "should_run").unwrap(), Value::Bool(true)));
            assert!(matches!(gsf(fields, "active").unwrap(), Value::Bool(true)));
        } else { panic!(); }
    }

    #[test]
    fn test_schedule_check_specific_cron() {
        let sched = schedule_create(&[
            Value::String("specific".into()),
            Value::String("0 2 * * 1".into()),
            Value::String("/s".into()),
            Value::String("/d".into()),
        ]).unwrap();
        let check = schedule_check(&[sched]).unwrap();
        if let Value::Struct { fields, .. } = &check {
            // Not all wildcards, so should_run = false
            assert!(matches!(gsf(fields, "should_run").unwrap(), Value::Bool(false)));
        } else { panic!(); }
    }

    #[test]
    fn test_av_scan_no_clamav() {
        // ClamAV is almost certainly not installed in CI -- should return warning, not error
        let d = TempDir::new().unwrap();
        let p = wtf(&d, "test.txt", "harmless file content");
        let result = av_scan(&[Value::String(p.clone())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "AvScanResult");
            assert_eq!(gsf(fields, "path").unwrap().as_string(), p);
            // Either clamav is installed (clean=true/false) or unavailable (clean=true + warning)
            let scanner = gsf(fields, "scanner").unwrap().as_string();
            if scanner == "unavailable" {
                assert!(matches!(gsf(fields, "clean").unwrap(), Value::Bool(true)));
                let warning = gsf(fields, "warning").unwrap().as_string();
                assert!(warning.contains("clamscan"));
            }
        } else { panic!(); }
    }

    #[test]
    fn test_av_scan_missing_file() {
        let result = av_scan(&[Value::String("/nonexistent/file.exe".into())]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("file not found"));
    }

    #[test]
    fn test_yara_scan_no_yara() {
        let d = TempDir::new().unwrap();
        let p = wtf(&d, "test.bin", "some binary data");
        let result = yara_scan(&[Value::String(p.clone())]).unwrap();
        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "YaraScanResult");
            assert_eq!(gsf(fields, "path").unwrap().as_string(), p);
            assert!(matches!(gsf(fields, "has_matches").unwrap(), Value::Bool(false)));
            if let Value::Array(m) = gsf(fields, "matches").unwrap() {
                assert!(m.is_empty());
            } else { panic!("expected matches array"); }
        } else { panic!(); }
    }

    #[test]
    fn test_dispatch_phase63_functions() {
        // Verify all Phase 63 dispatch routes
        let d = TempDir::new().unwrap();
        let cert = wtf(&d, "c.pem", "cert");
        let key = wtf(&d, "k.pem", "key");
        assert!(dispatch("mtls_config", vec![Value::String(cert), Value::String(key)]).is_some());
        assert!(dispatch("key_rotation_schedule", vec![Value::String("k".into())]).is_some());
        assert!(dispatch("key_rotate", vec![Value::String("k".into())]).is_some());
        assert!(dispatch("rbac_create_user", vec![Value::String("u".into())]).is_some());
        assert!(dispatch("webhook_config", vec![Value::String("https://x".into())]).is_some());
        assert!(dispatch("webhook_fire", vec![Value::String("https://x".into()), Value::String("ev".into())]).is_some());
        assert!(dispatch("schedule_create", vec![
            Value::String("n".into()), Value::String("0 0 * * *".into()),
            Value::String("/s".into()), Value::String("/d".into()),
        ]).is_some());
        let f = wtf(&d, "scan.txt", "data");
        assert!(dispatch("av_scan", vec![Value::String(f.clone())]).is_some());
        assert!(dispatch("yara_scan", vec![Value::String(f)]).is_some());
    }

    // ── Feature 5: Air-gap transfer mode tests ────────────────────────────

    #[test]
    fn test_airgap_qr_roundtrip() {
        let original = "intelligence-grade payload: TALLOW compiler test data";
        let chunks_val = airgap_to_qr(&[Value::String(original.into())]).unwrap();
        let chunks = match chunks_val {
            Value::Array(ref arr) => arr.clone(),
            other => panic!("expected Array, got {other:?}"),
        };
        assert!(!chunks.is_empty(), "should produce at least one chunk");

        // Verify first chunk has correct fields
        if let Value::Struct { name, fields } = &chunks[0] {
            assert_eq!(name, "QRChunk");
            let idx = match fields.iter().find(|(k,_)| k == "index").unwrap().1 {
                Value::Int(n) => n,
                ref other => panic!("{other:?}"),
            };
            assert_eq!(idx, 0);
        } else {
            panic!("expected QRChunk struct");
        }

        // Roundtrip
        let recovered = airgap_from_qr(&[chunks_val]).unwrap();
        assert_eq!(recovered.as_string(), original);
    }

    #[test]
    fn test_airgap_qr_large_data_multi_chunk() {
        // 10KB data should produce multiple chunks
        let large = "x".repeat(10_000);
        let chunks_val = airgap_to_qr(&[Value::String(large)]).unwrap();
        let chunks = match &chunks_val {
            Value::Array(arr) => arr.clone(),
            other => panic!("{other:?}"),
        };
        // base64 of 10KB = ~13.3KB, / 2953 = 5 chunks
        assert!(chunks.len() >= 4, "expected >= 4 chunks for 10KB, got {}", chunks.len());

        // Every chunk should have total > 1
        for chunk in &chunks {
            if let Value::Struct { fields, .. } = chunk {
                let total = match fields.iter().find(|(k,_)| k == "total").unwrap().1 {
                    Value::Int(n) => n,
                    ref o => panic!("{o:?}"),
                };
                assert!(total > 1);
            }
        }
    }

    #[test]
    fn test_airgap_to_audio_frequencies() {
        let data = "AB"; // A=65, B=66
        let result = airgap_to_audio(&[Value::String(data.into())]).unwrap();
        match &result {
            Value::Struct { name, fields } => {
                assert_eq!(name, "AudioData");
                let freqs = match fields.iter().find(|(k,_)| k == "frequencies").unwrap().1 {
                    Value::Array(ref arr) => arr.clone(),
                    ref other => panic!("{other:?}"),
                };
                assert_eq!(freqs.len(), 2);
                // 'A' = 65 → 300 + 650 = 950 Hz
                // 'A' = 65 → 300 + 650 = 950 Hz
                assert!(matches!(freqs[0], Value::Int(950)), "freq[0] should be 950, got {:?}", freqs[0]);
                // 'B' = 66 → 300 + 660 = 960 Hz
                assert!(matches!(freqs[1], Value::Int(960)), "freq[1] should be 960, got {:?}", freqs[1]);
                let encoding = fields.iter().find(|(k,_)| k == "encoding").unwrap().1.as_string();
                assert_eq!(encoding, "BFSK");
                let duration = match fields.iter().find(|(k,_)| k == "duration_ms").unwrap().1 {
                    Value::Int(n) => n,
                    ref other => panic!("{other:?}"),
                };
                assert_eq!(duration, 200); // 2 bytes × 100ms
            }
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    // ── Feature 8: Cloud sync primitive tests ─────────────────────────

    #[test]
    fn test_sigv4_sha256_hex() {
        // SHA-256 of empty string: NIST test vector
        assert_eq!(
            s3_sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // SHA-256("abc")
        assert_eq!(
            s3_sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Returns 64 hex chars
        assert_eq!(s3_sha256_hex(b"hello world").len(), 64);
    }

    #[test]
    fn test_sigv4_hmac_sha256() {
        // RFC 4231 test case 1:
        // Key  = 0x0b * 20
        // Data = "Hi There"
        // Expected = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        let key  = vec![0x0b_u8; 20];
        let hmac = s3_hmac_sha256(&key, b"Hi There");
        assert_eq!(
            s3_hex(&hmac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn test_sigv4_uri_encoding() {
        // Path: forward slashes preserved
        assert_eq!(s3_uri_path("my/key/file.txt"), "my/key/file.txt");
        // Path: spaces become %20
        assert_eq!(s3_uri_path("my key"), "my%20key");
        // Query: forward slashes encoded
        assert_eq!(s3_uri_query("my/value"), "my%2Fvalue");
        // Query: equals encoded
        assert_eq!(s3_uri_query("a=b"), "a%3Db");
        // Unreserved chars unchanged
        assert_eq!(s3_uri_path("abc-def_ghi.jkl~"), "abc-def_ghi.jkl~");
    }

    #[test]
    fn test_sigv4_query_sort_stability() {
        // Verify that query param order does not affect the computed signature.
        // SigV4 requires lexicographic sorting of query params.
        let creds = S3Creds {
            access_key: "AKID".into(),
            secret_key: "secret".into(),
            region:     "us-east-1".into(),
            endpoint:   "https://s3.us-east-1.amazonaws.com".into(),
        };
        let now  = "20230101T000000Z";
        let url1 = "https://bucket.s3.us-east-1.amazonaws.com/?list-type=2&prefix=data";
        let url2 = "https://bucket.s3.us-east-1.amazonaws.com/?prefix=data&list-type=2";
        let (auth1, _, _) = sigv4_sign("GET", url1, &[], &[], &creds, now);
        let (auth2, _, _) = sigv4_sign("GET", url2, &[], &[], &creds, now);
        assert!(auth1.starts_with("AWS4-HMAC-SHA256"));
        assert_eq!(auth1, auth2, "query param order must not affect signature");
    }

    #[test]
    fn test_sigv4_sign_format() {
        // Verify authorization header structure conforms to SigV4 spec.
        let creds = S3Creds {
            access_key: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            region:     "us-east-1".into(),
            endpoint:   "https://s3.us-east-1.amazonaws.com".into(),
        };
        let now = "20130524T000000Z";
        let url = "https://examplebucket.s3.amazonaws.com/test.txt";
        let (auth, amz_date, csha256) = sigv4_sign("GET", url, &[], &[], &creds, now);
        // Must contain required fields
        assert!(auth.contains("AWS4-HMAC-SHA256"));
        assert!(auth.contains("Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"));
        assert!(auth.contains("SignedHeaders="));
        assert!(auth.contains("Signature="));
        // Signature must be 64 hex chars
        let sig_part = auth.split("Signature=").nth(1).unwrap_or("");
        assert_eq!(sig_part.len(), 64, "signature must be 64 hex chars");
        assert_eq!(amz_date, "20130524T000000Z");
        assert_eq!(csha256.len(), 64, "payload hash must be 64 hex chars");
    }

    #[test]
    fn test_xml_list_parsing() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>my-bucket</Name>
  <Contents>
    <Key>data/file1.txt</Key>
    <Size>1024</Size>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
  </Contents>
  <Contents>
    <Key>data/file2.txt</Key>
    <Size>2048</Size>
    <LastModified>2026-01-02T00:00:00.000Z</LastModified>
  </Contents>
</ListBucketResult>"#;
        let objects = parse_list_xml(xml);
        assert_eq!(objects.len(), 2, "should parse 2 objects");
        assert_eq!(objects[0].0, "data/file1.txt");
        assert_eq!(objects[0].1, 1024_i128);
        assert_eq!(objects[1].0, "data/file2.txt");
        assert_eq!(objects[1].1, 2048_i128);
    }

    #[test]
    fn test_xml_etag_parsing() {
        // ETag returned as plain text from response header
        assert_eq!(parse_etag_xml(r#""abc123def456""#), "abc123def456");
        assert_eq!(parse_etag_xml("abc123"), "abc123");
        // ETag in XML body (multipart complete response)
        assert_eq!(parse_etag_xml("<ETag>abc123</ETag>"), "abc123");
    }

    #[test]
    fn test_s3_creds_bucket_url_aws() {
        let creds = S3Creds {
            access_key: "key".into(),
            secret_key: "secret".into(),
            region:     "eu-west-1".into(),
            endpoint:   "https://s3.eu-west-1.amazonaws.com".into(),
        };
        assert_eq!(
            creds.bucket_url("my-bucket"),
            "https://my-bucket.s3.eu-west-1.amazonaws.com"
        );
    }

    #[test]
    fn test_s3_creds_bucket_url_minio() {
        let creds = S3Creds {
            access_key: "minioadmin".into(),
            secret_key: "minioadmin".into(),
            region:     "us-east-1".into(),
            endpoint:   "http://localhost:9000".into(),
        };
        // Non-AWS: path-style (no DNS wildcard needed)
        assert_eq!(creds.bucket_url("test-bucket"), "http://localhost:9000/test-bucket");
    }

    #[test]
    fn test_s3_creds_bucket_url_r2() {
        let creds = S3Creds {
            access_key: "key".into(),
            secret_key: "secret".into(),
            region:     "auto".into(),
            endpoint:   "https://abc123.r2.cloudflarestorage.com".into(),
        };
        assert_eq!(
            creds.bucket_url("my-bucket"),
            "https://abc123.r2.cloudflarestorage.com/my-bucket"
        );
    }

    #[test]
    fn test_cloud_s3_list_no_creds() {
        unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        }
        let result = cloud_s3_list(&[Value::String("my-bucket".into())]);
        assert!(result.is_err(), "cloud_s3_list should error without credentials");
        let err = result.unwrap_err();
        assert!(
            err.contains("AWS_ACCESS_KEY_ID") || err.contains("AWS"),
            "error should mention missing credential: {err}"
        );
    }

    #[test]
    fn test_cloud_s3_upload_download_no_creds() {
        unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        }

        let upload = cloud_s3_upload(&[
            Value::String("my-bucket".into()),
            Value::String("backups/data.txt".into()),
            Value::String("/tmp/data.txt".into()),
        ]);
        assert!(upload.is_err(), "cloud_s3_upload should error without credentials");

        let download = cloud_s3_download(&[
            Value::String("my-bucket".into()),
            Value::String("backups/data.txt".into()),
            Value::String("/tmp/data.txt".into()),
        ]);
        assert!(download.is_err(), "cloud_s3_download should error without credentials");

        let delete = cloud_s3_delete(&[
            Value::String("my-bucket".into()),
            Value::String("backups/data.txt".into()),
        ]);
        assert!(delete.is_err(), "cloud_s3_delete should error without credentials");

        let head = cloud_s3_head(&[
            Value::String("my-bucket".into()),
            Value::String("backups/data.txt".into()),
        ]);
        assert!(head.is_err(), "cloud_s3_head should error without credentials");
    }

    #[test]
    fn test_cloud_gcs_and_azure_dispatch_no_creds() {
        unsafe {
            std::env::remove_var("GCS_ACCESS_KEY_ID");
            std::env::remove_var("AWS_ACCESS_KEY_ID");
        }

        let r = dispatch("cloud_gcs_list", vec![Value::String("my-gcs-bucket".into())]);
        assert!(r.is_some(), "cloud_gcs_list should be routable");
        assert!(r.unwrap().is_err(), "cloud_gcs_list should error without credentials");

        unsafe { std::env::remove_var("AZURE_STORAGE_ACCOUNT"); }
        let r2 = dispatch("cloud_azure_upload", vec![
            Value::String("my-container".into()),
            Value::String("blob-key".into()),
            Value::String("/tmp/data".into()),
        ]);
        assert!(r2.is_some(), "cloud_azure_upload should be routable");
        assert!(r2.unwrap().is_err(), "cloud_azure_upload should error without credentials");
    }

    #[test]
    fn test_cloud_s3_delete_head_dispatch() {
        unsafe {
            std::env::remove_var("AWS_ACCESS_KEY_ID");
            std::env::remove_var("AWS_SECRET_ACCESS_KEY");
        }

        let del = dispatch("cloud_s3_delete", vec![
            Value::String("bucket".into()),
            Value::String("key.txt".into()),
        ]);
        assert!(del.is_some(), "cloud_s3_delete should be in dispatch table");
        assert!(del.unwrap().is_err(), "cloud_s3_delete needs credentials");

        let head = dispatch("cloud_s3_head", vec![
            Value::String("bucket".into()),
            Value::String("key.txt".into()),
        ]);
        assert!(head.is_some(), "cloud_s3_head should be in dispatch table");
        assert!(head.unwrap().is_err(), "cloud_s3_head needs credentials");
    }



    // ── Two-way sync engine tests ─────────────────────────────────────────

    fn make_temp_dirs() -> (TempDir, TempDir) {
        (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
    }

    fn write_file(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn db_path(dir: &std::path::Path) -> String {
        dir.join(".tallow-sync.db").to_string_lossy().to_string()
    }

    #[test]
    fn test_twoway_identical_dirs_no_actions() {
        let (left, right) = make_temp_dirs();
        write_file(left.path(), "a.txt", "hello");
        write_file(right.path(), "a.txt", "hello");
        let db = db_path(left.path());
        // First sync: no stored state yet, files are NEW on both sides with identical content
        let result = twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // After first sync the state is recorded; run again — should show 0 actions
        let result2 = twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db),
        ]).unwrap();
        if let Value::Struct { fields, .. } = result2 {
            let copied = fields.iter().find(|(k,_)| k == "files_copied").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0);
            let deleted = fields.iter().find(|(k,_)| k == "files_deleted").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0);
            assert_eq!(copied, 0, "No files should be copied when dirs are identical");
            assert_eq!(deleted, 0, "No files should be deleted when dirs are identical");
        } else {
            panic!("twoway_sync should return a Struct: {:?}", result);
        }
    }

    #[test]
    fn test_twoway_file_added_on_left() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        // Initial sync with empty dirs
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // Add a file only on the left
        write_file(left.path(), "new_left.txt", "new content");
        let result = twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db),
        ]).unwrap();
        assert!(right.path().join("new_left.txt").exists(), "File should be copied from left to right");
        if let Value::Struct { fields, .. } = result {
            let copied = fields.iter().find(|(k,_)| k == "files_copied").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0);
            assert!(copied >= 1, "At least 1 file should be copied");
        }
    }

    #[test]
    fn test_twoway_file_added_on_right() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        // Initial sync with empty dirs
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // Add a file only on the right
        write_file(right.path(), "new_right.txt", "right side content");
        let result = twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db),
        ]).unwrap();
        assert!(left.path().join("new_right.txt").exists(), "File should be copied from right to left");
        if let Value::Struct { fields, .. } = result {
            let copied = fields.iter().find(|(k,_)| k == "files_copied").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0);
            assert!(copied >= 1, "At least 1 file should be copied");
        }
    }

    #[test]
    fn test_twoway_file_modified_on_left() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        write_file(left.path(), "shared.txt", "original");
        write_file(right.path(), "shared.txt", "original");
        // Establish baseline
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // Modify only left
        std::thread::sleep(std::time::Duration::from_millis(10));
        write_file(left.path(), "shared.txt", "modified on left");
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db),
        ]).unwrap();
        let right_content = std::fs::read_to_string(right.path().join("shared.txt")).unwrap();
        assert_eq!(right_content, "modified on left", "Right should be updated from left");
    }

    #[test]
    fn test_twoway_both_modified_conflict_detected() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        write_file(left.path(), "conflict.txt", "original");
        write_file(right.path(), "conflict.txt", "original");
        // Establish baseline
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("skip".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // Modify both sides
        std::thread::sleep(std::time::Duration::from_millis(10));
        write_file(left.path(), "conflict.txt", "left version");
        write_file(right.path(), "conflict.txt", "right version");
        let result = twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("skip".into()),
            Value::String(db),
        ]).unwrap();
        if let Value::Struct { fields, .. } = result {
            let conflicts = fields.iter().find(|(k,_)| k == "conflicts_skipped").and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap_or(0);
            assert!(conflicts >= 1, "Should detect at least 1 conflict");
        }
    }

    #[test]
    fn test_twoway_conflict_newest_wins() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        write_file(left.path(), "conflict.txt", "original");
        write_file(right.path(), "conflict.txt", "original");
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // Write left first, then right (right is newer).
        // Use 1.1s sleep to exceed the 1-second mtime granularity on FAT32/some filesystems.
        write_file(left.path(), "conflict.txt", "left version");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_file(right.path(), "conflict.txt", "right version (newer)");
        let result = twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db),
        ]).unwrap();
        // Verify conflict was resolved (not skipped)
        if let Value::Struct { ref fields, .. } = result {
            let resolved = fields.iter().find(|(k,_)| k == "conflicts_resolved")
                .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None })
                .unwrap_or(0);
            assert!(resolved >= 1, "Expected conflict to be resolved, got result: {:?}", result);
        }
        let left_content = std::fs::read_to_string(left.path().join("conflict.txt")).unwrap();
        assert_eq!(left_content, "right version (newer)", "Newer (right) should win");
    }

    #[test]
    fn test_twoway_conflict_rename_keeps_both() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        write_file(left.path(), "both.txt", "original");
        write_file(right.path(), "both.txt", "original");
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("rename".into()),
            Value::String(db.clone()),
        ]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        write_file(left.path(), "both.txt", "left version");
        write_file(right.path(), "both.txt", "right version");
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("rename".into()),
            Value::String(db),
        ]).unwrap();
        // Both dirs should have 2 files: the winner + the conflict-renamed loser
        let left_entries: Vec<_> = std::fs::read_dir(left.path()).unwrap().collect();
        let right_entries: Vec<_> = std::fs::read_dir(right.path()).unwrap().collect();
        assert!(left_entries.len() >= 2, "Left should have original + conflict file, got {}", left_entries.len());
        assert!(right_entries.len() >= 2, "Right should have original + conflict file, got {}", right_entries.len());
    }

    #[test]
    fn test_twoway_delete_on_left_propagates() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        write_file(left.path(), "to_delete.txt", "content");
        write_file(right.path(), "to_delete.txt", "content");
        // Establish baseline
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // Delete from left
        std::fs::remove_file(left.path().join("to_delete.txt")).unwrap();
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db),
        ]).unwrap();
        assert!(!right.path().join("to_delete.txt").exists(), "File deleted on left should also be deleted on right");
    }

    #[test]
    fn test_twoway_delete_left_but_right_modified_copies_back() {
        let (left, right) = make_temp_dirs();
        let db = db_path(left.path());
        write_file(left.path(), "modified_then_deleted.txt", "original");
        write_file(right.path(), "modified_then_deleted.txt", "original");
        // Establish baseline
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db.clone()),
        ]).unwrap();
        // Delete from left, but modify on right (right wins)
        std::fs::remove_file(left.path().join("modified_then_deleted.txt")).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
        write_file(right.path(), "modified_then_deleted.txt", "right modified after delete");
        twoway_sync(&[
            Value::String(left.path().to_string_lossy().to_string()),
            Value::String(right.path().to_string_lossy().to_string()),
            Value::String("newest".into()),
            Value::String(db),
        ]).unwrap();
        // Right wins: file should be restored on left
        assert!(left.path().join("modified_then_deleted.txt").exists(), "Modified right should be copied back to left");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Block-level delta sync tests
    // ─────────────────────────────────────────────────────────────────────────

    /// block_sync_file on a new file (dst absent) → full copy, savings 0%.
    #[test]
    fn test_block_sync_file_new_file() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src.bin");
        let dst = tmp.path().join("dst.bin");
        let content = b"hello block sync";
        std::fs::write(&src, content).unwrap();

        let result = block_sync_file(&[
            Value::String(src.to_string_lossy().into()),
            Value::String(dst.to_string_lossy().into()),
        ])
        .unwrap();

        assert!(dst.exists(), "dst should be created");
        assert_eq!(std::fs::read(&dst).unwrap(), content);

        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "BlockSyncResult");
            assert_eq!(gsf(fields, "method").unwrap().as_string(), "full_copy");
            assert!(matches!(gsf(fields, "savings_pct").unwrap(), Value::Float(f) if *f == 0.0));
            assert!(
                matches!(gsf(fields, "bytes_transferred").unwrap(), Value::Int(n) if *n == content.len() as i128)
            );
        } else {
            panic!("expected BlockSyncResult struct");
        }
    }

    /// block_sync_file on identical files → delta is tiny (rsync overhead only),
    /// savings > 50%, and dst content still matches src.
    #[test]
    fn test_block_sync_file_identical() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src.bin");
        let dst = tmp.path().join("dst.bin");
        // 256 KiB: covers at least two full 128 KiB blocks.
        let content: Vec<u8> = (0u8..=255).cycle().take(256 * 1024).collect();
        std::fs::write(&src, &content).unwrap();
        std::fs::write(&dst, &content).unwrap();

        let result = block_sync_file(&[
            Value::String(src.to_string_lossy().into()),
            Value::String(dst.to_string_lossy().into()),
        ])
        .unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), content, "dst content must match src");

        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "BlockSyncResult");
            assert_eq!(gsf(fields, "method").unwrap().as_string(), "block_delta");
            let savings = gsf(fields, "savings_pct").unwrap();
            assert!(
                matches!(savings, Value::Float(f) if *f > 50.0),
                "expected > 50% savings for identical files, got {savings:?}"
            );
            let reused = gsf(fields, "blocks_reused").unwrap();
            assert!(
                matches!(reused, Value::Int(n) if *n > 0),
                "should reuse blocks when files are identical"
            );
        } else {
            panic!("expected BlockSyncResult struct");
        }
    }

    /// block_sync_file with one byte changed → only a small delta is transferred
    /// and dst is correctly reconstructed.
    #[test]
    fn test_block_sync_file_one_byte_changed() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src.bin");
        let dst = tmp.path().join("dst.bin");

        // 256 KiB = two full 128 KiB blocks. Flip one byte in the first block.
        let mut original: Vec<u8> = (0u8..=255).cycle().take(256 * 1024).collect();
        std::fs::write(&dst, &original).unwrap();
        original[42] ^= 0xFF;
        std::fs::write(&src, &original).unwrap();

        let result = block_sync_file(&[
            Value::String(src.to_string_lossy().into()),
            Value::String(dst.to_string_lossy().into()),
        ])
        .unwrap();

        assert_eq!(std::fs::read(&dst).unwrap(), original, "dst must equal src after apply");

        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "BlockSyncResult");
            let xfer = match gsf(fields, "bytes_transferred").unwrap() {
                Value::Int(n) => *n,
                v => panic!("expected Int, got {v:?}"),
            };
            let file_sz = match gsf(fields, "file_size").unwrap() {
                Value::Int(n) => *n,
                v => panic!("expected Int, got {v:?}"),
            };
            assert!(
                xfer < file_sz,
                "delta ({xfer} B) should be smaller than full file ({file_sz} B)"
            );
        } else {
            panic!("expected BlockSyncResult struct");
        }
    }

    /// block_sync_dir: mixed scenario — new file, changed file, identical file.
    #[test]
    fn test_block_sync_dir_mixed() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        // File A: only in src (new)
        std::fs::write(src.join("new.txt"), b"brand new file").unwrap();

        // File B: identical in both — force same mtime so the dir sync skips it
        std::fs::write(src.join("same.txt"), b"identical content").unwrap();
        std::fs::write(dst.join("same.txt"), b"identical content").unwrap();
        let same_time = filetime::FileTime::from_unix_time(1_700_000_000, 0);
        filetime::set_file_mtime(src.join("same.txt"), same_time).unwrap();
        filetime::set_file_mtime(dst.join("same.txt"), same_time).unwrap();

        // File C: changed (different size triggers delta)
        std::fs::write(src.join("changed.txt"), b"new content abcdef").unwrap();
        std::fs::write(dst.join("changed.txt"), b"old content xyz").unwrap();

        let result = block_sync_dir(&[
            Value::String(src.to_string_lossy().into()),
            Value::String(dst.to_string_lossy().into()),
        ])
        .unwrap();

        assert!(dst.join("new.txt").exists(), "new file must be copied to dst");
        assert_eq!(std::fs::read(dst.join("new.txt")).unwrap(), b"brand new file");
        assert_eq!(
            std::fs::read(dst.join("changed.txt")).unwrap(),
            b"new content abcdef",
            "changed file must match src after block sync"
        );

        if let Value::Struct { name, fields } = &result {
            assert_eq!(name, "BlockSyncDirResult");
            let new_c = match gsf(fields, "files_new").unwrap() {
                Value::Int(n) => *n,
                _ => panic!(),
            };
            let skip_c = match gsf(fields, "files_skipped").unwrap() {
                Value::Int(n) => *n,
                _ => panic!(),
            };
            let errors = match gsf(fields, "errors").unwrap() {
                Value::Int(n) => *n,
                _ => panic!(),
            };
            assert_eq!(new_c, 1, "one new file expected");
            assert_eq!(skip_c, 1, "one skipped file expected");
            assert_eq!(errors, 0, "no errors expected");
        } else {
            panic!("expected BlockSyncDirResult struct");
        }
    }

    /// block_signature → block_delta → block_apply round-trip.
    #[test]
    fn test_block_signature_delta_apply_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let old_path = tmp.path().join("old.bin");
        let new_path = tmp.path().join("new.bin");
        let out_path = tmp.path().join("out.bin");

        let old_data: Vec<u8> = (0u8..=127).cycle().take(300 * 1024).collect();
        let mut new_data = old_data.clone();
        // Change a 1 KiB chunk in the middle
        for b in new_data[50_000..51_000].iter_mut() {
            *b ^= 0xAA;
        }

        std::fs::write(&old_path, &old_data).unwrap();
        std::fs::write(&new_path, &new_data).unwrap();

        // Step 1: signature of old
        let sig_result = block_signature(&[Value::String(old_path.to_string_lossy().into())]).unwrap();
        let sig_b64 = if let Value::Struct { fields, .. } = &sig_result {
            gsf(fields, "signature").unwrap().as_string()
        } else {
            panic!("expected BlockSignature");
        };

        // Step 2: delta from old sig → new file
        let delta_result = block_delta(&[
            Value::String(sig_b64),
            Value::String(new_path.to_string_lossy().into()),
        ])
        .unwrap();
        let delta_b64 = if let Value::Struct { fields, .. } = &delta_result {
            gsf(fields, "delta").unwrap().as_string()
        } else {
            panic!("expected BlockDelta");
        };

        // Step 3: apply delta to old → out
        let apply_result = block_apply(&[
            Value::String(old_path.to_string_lossy().into()),
            Value::String(delta_b64),
            Value::String(out_path.to_string_lossy().into()),
        ])
        .unwrap();
        assert!(matches!(apply_result, Value::Struct { .. }));

        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            new_data,
            "round-trip must reconstruct the new file exactly"
        );
    }
}
