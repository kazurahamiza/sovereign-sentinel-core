use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use rand::RngCore;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

pub struct QuarantineManager {
    vault_path: String,
    cipher: Aes256Gcm,
}

impl QuarantineManager {
    pub fn new(vault_path: &str, master_key: &[u8; 32]) -> Self {
        fs::create_dir_all(vault_path).expect("Failed to create quarantine vault.");
        let key = Key::<Aes256Gcm>::from_slice(master_key);
        let cipher = Aes256Gcm::new(key);
        
        Self {
            vault_path: vault_path.to_string(),
            cipher,
        }
    }

    /// Encrypts and moves target malicious executable into the vault
    pub fn quarantine_file(&self, target_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let path = Path::new(target_path);
        if !path.exists() {
            return Err("Target file does not exist.".into());
        }

        // 1. Read raw binary
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        // 2. Generate random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // 3. Encrypt file payload
        let ciphertext = self.cipher.encrypt(nonce, buffer.as_ref())
            .map_err(|_| "Encryption failed during quarantine execution.")?;

        // 4. Save to Vault with Nonce Prepended
        let file_name = path.file_name().unwrap().to_str().unwrap();
        let vault_file_path = format!("{}/{}.qvault", self.vault_path, file_name);
        let mut vault_file = File::create(&vault_file_path)?;

        vault_file.write_all(&nonce_bytes)?;
        vault_file.write_all(&ciphertext)?;

        // 5. Remove original file from disk
        fs::remove_file(path)?;

        println!("[+] Quarantine Successful: {} -> {}", target_path, vault_file_path);
        Ok(())
    }
}
