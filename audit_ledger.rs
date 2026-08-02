use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

#[derive(Debug)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub event_id: u32,
    pub source_module: String,
    pub description: String,
}

pub struct ImmutableLogger {
    log_file_path: String,
    last_hash: Mutex<String>,
}

impl ImmutableLogger {
    pub fn new(file_path: &str, genesis_seed: &str) -> Self {
        Self {
            log_file_path: file_path.to_string(),
            last_hash: Mutex::new(genesis_seed.to_string()),
        }
    }

    /// Appends a new audit record to the ledger with hash chaining
    pub fn log_event(&self, entry: AuditEntry) -> Result<(), Box<dyn std::error::Error>> {
        let mut last_hash_guard = self.last_hash.lock().unwrap();

        // 1. Serialize entry data
        let payload = format!(
            "{}:{}:{}:{}",
            entry.timestamp, entry.event_id, entry.source_module, entry.description
        );

        // 2. Compute current record hash: SHA256(PreviousHash + Payload)
        let mut hasher = Sha256::new();
        hasher.update(last_hash_guard.as_bytes());
        hasher.update(payload.as_bytes());
        let current_hash = format!("{:x}", hasher.finalize());

        // 3. Format structured log output
        let record = format!(
            "{{\"prev_hash\":\"{}\",\"hash\":\"{}\",\"data\":{{\"time\":{},\"id\":{},\"src\":\"{}\",\"desc\":\"{}\"}}}}\n",
            *last_hash_guard, current_hash, entry.timestamp, entry.event_id, entry.source_module, entry.description
        );

        // 4. Atomic append to disk log
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)?;
        file.write_all(record.as_bytes())?;

        // 5. Update state hash
        *last_hash_guard = current_hash;

        Ok(())
    }
}
