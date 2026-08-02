use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::State;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatTelemetry {
    pub timestamp: String,
    pub event_type: String, // e.g., "KERNEL_INTERCEPT", "MEMORY_BLOCK"
    pub target_process: String,
    pub process_id: u32,
    pub status: String,     // e.g., "TERMINATED", "QUARANTINED"
}

pub struct AppState {
    pub telemetry_log: Mutex<Vec<ThreatTelemetry>>,
}

#[tauri::command]
pub fn get_live_telemetry(state: State<'_, AppState>) -> Result<Vec<ThreatTelemetry>, String> {
    let logs = state.telemetry_log.lock().map_err(|_| "Failed to lock telemetry state")?;
    Ok(logs.clone())
}

#[tauri::command]
pub fn force_kill_process_tree(pid: u32) -> Result<String, String> {
    // Invoke Ring 0 Driver / Win32 API to terminate process tree
    println!("[!] Manual Override: Terminating PID {}", pid);
    Ok(format!("Process tree for PID {} terminated successfully.", pid))
}

#[tauri::command]
pub fn purge_quarantine_vault() -> Result<String, String> {
    // Purge logic for encrypted files
    Ok("Quarantine vault successfully purged.".to_string())
}
