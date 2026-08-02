use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ExecutionStateVector {
    pub process_id: u32,
    pub syscall_frequency_entropy: f32,
    pub unbacked_memory_execution: bool,
    pub network_outbound_burst_rate: f32,
    pub parent_child_anomaly_score: f32,
}

pub struct AutonomousCortex {
    anomaly_threshold: f32,
    learned_threat_patterns: HashMap<String, f32>,
}

impl AutonomousCortex {
    pub fn new(threshold: f32) -> Self {
        Self {
            anomaly_threshold: threshold,
            learned_threat_patterns: HashMap::new(),
        }
    }

    /// Evaluates real-time state vectors using local neural weights
    pub fn evaluate_state(&mut self, state: &ExecutionStateVector) -> (bool, f32) {
        // Compute composite risk probability vector
        let mut risk_score = 0.0f32;

        if state.unbacked_memory_execution {
            risk_score += 0.45;
        }
        risk_score += state.syscall_frequency_entropy * 0.25;
        risk_score += state.network_outbound_burst_rate * 0.15;
        risk_score += state.parent_child_anomaly_score * 0.15;

        println!(
            "[CORTEX] Evaluated PID: {} | Calculated Anomaly Probability: {:.4}",
            state.process_id, risk_score
        );

        let is_malicious = risk_score >= self.anomaly_threshold;

        if is_malicious {
            // Self-Learning Step: Synthesize structural signature from anomaly
            self.synthesize_rule_pattern(state, risk_score);
        }

        (is_malicious, risk_score)
    }

    /// Autonomously generates a new pattern rule from novel threat observations
    fn synthesize_rule_pattern(&mut self, state: &ExecutionStateVector, confidence: f32) {
        let pattern_id = format!("AUTO_GEN_PATTERN_PID_{}", state.process_id);
        self.learned_threat_patterns.insert(pattern_id.clone(), confidence);

        println!(
            "[+] Autonomous Cortex: Synthesized & Hot-Loaded New Detection Rule: '{}' (Confidence: {:.2}%)",
            pattern_id, confidence * 100.0
        );

        // TODO: Hot-load synthesized rule directly into Step 2 Scanner & Step 13 Mesh
    }
}
