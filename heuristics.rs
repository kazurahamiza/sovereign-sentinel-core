use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub enum ProcessBehavior {
    ExecFromTemp,
    OfficeAppSpawnedCmd,
    ClearedEventLogs,
    ShadowCopyDeletionAttempt,
    EncodedPowerShell,
}

pub struct BehavioralEngine {
    // Maps Process ID (PID) to accumulated risk score
    process_risk_map: Mutex<HashMap<u32, u32>>,
    risk_threshold: u32,
}

impl BehavioralEngine {
    pub fn new(threshold: u32) -> Self {
        Self {
            process_risk_map: Mutex::new(HashMap::new()),
            risk_threshold: threshold,
        }
    }

    /// Evaluates an intercepted process action and updates its cumulative score
    pub fn register_event(&self, pid: u32, behavior: ProcessBehavior) -> bool {
        let weight = match behavior {
            ProcessBehavior::ExecFromTemp => 15,
            ProcessBehavior::OfficeAppSpawnedCmd => 25,
            ProcessBehavior::EncodedPowerShell => 30,
            ProcessBehavior::ClearedEventLogs => 40,
            ProcessBehavior::ShadowCopyDeletionAttempt => 50,
        };

        let mut map = self.process_risk_map.lock().unwrap();
        let current_score = map.entry(pid).or_insert(0);
        *current_score += weight;

        println!("[HEURISTICS] PID: {} | Action: {:?} | Current Score: {}", pid, behavior, *current_score);

        // Returns true if process breaches safety threshold
        *current_score >= self.risk_threshold
    }

    pub fn purge_process(&self, pid: u32) {
        let mut map = self.process_risk_map.lock().unwrap();
        map.remove(&pid);
    }
}
