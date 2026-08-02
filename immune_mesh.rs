use ed25519_dalek::{Keypair, Signature, Signer, Verifier, PublicKey};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ThreatImmunizationPayload {
    pub timestamp: u64,
    pub sha256_hash: String,
    pub rule_pattern: String, // e.g., YARA or byte offset pattern
    pub reporter_node_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedImmunizationBundle {
    pub payload: ThreatImmunizationPayload,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub struct ImmuneMeshNode {
    keypair: Keypair,
    node_id: String,
}

impl ImmuneMeshNode {
    pub fn new(keypair: Keypair, node_id: &str) -> Self {
        Self {
            keypair,
            node_id: node_id.to_string(),
        }
    }

    /// Creates and signs a new threat immunization bundle upon local detection
    pub fn generate_immunization(&self, threat_hash: &str, rule: &str) -> SignedImmunizationBundle {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        
        let payload = ThreatImmunizationPayload {
            timestamp: now,
            sha256_hash: threat_hash.to_string(),
            rule_pattern: rule.to_string(),
            reporter_node_id: self.node_id.clone(),
        };

        let serialized_payload = serde_json::to_vec(&payload).unwrap();
        let signature = self.keypair.sign(&serialized_payload);

        SignedImmunizationBundle {
            payload,
            signature: signature.to_bytes().to_vec(),
            public_key: self.keypair.public.to_bytes().to_vec(),
        }
    }

    /// Verifies incoming immunization bundle from a peer node before kernel injection
    pub fn verify_and_process_bundle(&self, bundle: &SignedImmunizationBundle) -> bool {
        let public_key = match PublicKey::from_bytes(&bundle.public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let signature = match Signature::from_bytes(&bundle.signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let serialized_payload = match serde_json::to_string(&bundle.payload) {
            Ok(json) => json,
            Err(_) => return false,
        };

        // Validate cryptographic authenticity
        if public_key.verify(serialized_payload.as_bytes(), &signature).is_ok() {
            println!(
                "[+] Immune Mesh: Valid signature from node {}. Injecting hash {} into Ring 0 Blocklist.",
                bundle.payload.reporter_node_id, bundle.payload.sha256_hash
            );
            // TODO: Call Step 1 / Step 12 driver interface to update in-memory blocklists
            return true;
        }

        println!("[-] Immune Mesh Error: Cryptographic signature validation failed!");
        false
    }
}
